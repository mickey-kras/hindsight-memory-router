from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import Request

from memory_router import app as app_module
from memory_router.errors import HttpError
from memory_router.hindsight import HindsightGatewayError


def request(
    method: str,
    path: str,
    *,
    body: object | bytes | None = None,
    headers: dict[str, str] | None = None,
    query: str = "",
) -> Request:
    if isinstance(body, bytes):
        raw = body
    elif body is None:
        raw = b""
    else:
        raw = json.dumps(body).encode()
    header_values = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": header_values,
        "query_string": query.encode(),
    }
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return Request(scope, receive)


def payload(response: object) -> object:
    return json.loads(response.body)  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def runtime_state() -> None:
    app_module.runtime.allow_anonymous = True
    app_module.runtime.router_token = None
    app_module.runtime.admin_tokens = {
        "legacy": "admin",
        "read": None,
        "review": None,
        "cleanup": None,
    }
    app_module.runtime.max_body_bytes = 1024
    app_module.runtime.admin_read_max = 120
    app_module.runtime.admin_write_max = 30
    app_module.runtime.admin_window = 60_000
    app_module.runtime.admin_limiter = SimpleNamespace(consume_many=AsyncMock())
    app_module.runtime.auditor = SimpleNamespace(record=AsyncMock())


@pytest.mark.asyncio
async def test_health_ready_and_exception_handlers(capsys: pytest.CaptureFixture[str]) -> None:
    assert await app_module.health() == {"status": "healthy", "service": "memory-router"}
    app_module.runtime.repository = SimpleNamespace(ping=AsyncMock())
    assert payload(await app_module.ready()) == {"status": "ready", "service": "memory-router"}
    app_module.runtime.repository.ping.side_effect = RuntimeError("down")
    response = await app_module.ready()
    assert response.status_code == 503 and payload(response)["status"] == "not_ready"

    response = await app_module.http_error_handler(
        request("GET", "/"), HttpError(429, "limited", "slow", {"retry-after": "2"})
    )
    assert response.status_code == 429 and response.headers["retry-after"] == "2"
    gateway = HindsightGatewayError("network", operation="recall", method="POST")
    response = await app_module.unhandled_handler(request("GET", "/"), gateway)
    assert response.status_code == 502 and payload(response)["error"] == "hindsight_unavailable"
    assert "upstream request failed" in capsys.readouterr().err
    response = await app_module.unhandled_handler(request("GET", "/"), RuntimeError("secret"))
    assert response.status_code == 500 and payload(response)["error"] == "internal_error"
    assert "request failed" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_json_body_bounds_and_invalid_json() -> None:
    app_module.runtime.max_body_bytes = 3
    with pytest.raises(HttpError) as declared:
        await app_module._json_body(
            request("POST", "/", body=b"{}", headers={"content-length": "4"})
        )
    assert declared.value.status == 413
    with pytest.raises(HttpError) as actual:
        await app_module._json_body(request("POST", "/", body=b"1234"))
    assert actual.value.code == "request_body_too_large"
    app_module.runtime.max_body_bytes = 100
    with pytest.raises(HttpError) as invalid:
        await app_module._json_body(request("POST", "/", body=b"{"))
    assert invalid.value.code == "invalid_json"
    assert await app_module._json_body(request("POST", "/", body={"x": 1})) == {"x": 1}


@pytest.mark.asyncio
async def test_router_and_admin_auth_failures_are_audited() -> None:
    app_module.runtime.allow_anonymous = False
    app_module.runtime.router_token = "router"
    assert not await app_module._router_auth(request("GET", "/version"))
    app_module.runtime.auditor.record.assert_awaited_with("router")
    assert await app_module._router_auth(
        request("GET", "/version", headers={"authorization": "Bearer router"})
    )
    assert not await app_module._admin_auth(request("GET", "/admin/quarantine/stats"), "read")
    app_module.runtime.auditor.record.assert_awaited_with("admin")
    assert await app_module._admin_auth(
        request(
            "GET",
            "/admin/quarantine/stats",
            headers={"authorization": "Bearer admin"},
        ),
        "read",
    )


@pytest.mark.asyncio
async def test_admin_rate_mapping() -> None:
    await app_module._admin_rate("GET")
    assert "admin:read" in str(app_module.runtime.admin_limiter.consume_many.await_args)
    app_module.runtime.admin_limiter.consume_many.side_effect = HttpError(429, "x", "x")
    with pytest.raises(HttpError) as limited:
        await app_module._admin_rate("POST")
    assert limited.value.code == "admin_rate_limited"
    app_module.runtime.admin_limiter.consume_many.side_effect = HttpError(500, "x", "x")
    with pytest.raises(HttpError) as passthrough:
        await app_module._admin_rate("POST")
    assert passthrough.value.status == 500


@pytest.mark.asyncio
async def test_router_dispatch_version_retain_recall_and_denied() -> None:
    limits = SimpleNamespace(assert_retain_bounds=AsyncMock(), assert_recall_bounds=AsyncMock())
    policy = SimpleNamespace(
        limits=limits,
        retain=AsyncMock(return_value={"retained": True}),
        recall=AsyncMock(return_value={"results": []}),
        deny_endpoint=AsyncMock(return_value={"error": "endpoint_not_allowed"}),
    )
    app_module.runtime.policy = policy

    response = await app_module.dispatch("version", request("GET", "/version"))
    assert response.status_code == 200 and payload(response)["api_version"] == "0.9.0"

    response = await app_module.dispatch(
        "v1/default/banks/main/memories",
        request("POST", "/v1/default/banks/main/memories", body={"items": [{"content": "ok"}]}),
    )
    assert payload(response) == {"retained": True}
    policy.retain.assert_awaited_once()

    response = await app_module.dispatch(
        "v1/default/banks/main/memories/recall",
        request(
            "POST",
            "/v1/default/banks/main/memories/recall",
            body={"query": "hello", "trace": False},
        ),
    )
    assert payload(response) == {"results": []}
    policy.recall.assert_awaited_once()

    response = await app_module.dispatch("missing", request("GET", "/missing"))
    assert response.status_code == 404 and payload(response)["error"] == "endpoint_not_allowed"

    app_module.runtime.allow_anonymous = False
    response = await app_module.dispatch("version", request("GET", "/version"))
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_admin_dispatch_all_routes_and_validation() -> None:
    admin = SimpleNamespace(
        list_queue=AsyncMock(return_value={"items": []}),
        stats=AsyncMock(return_value={"total_items": 0}),
        cleanup=AsyncMock(return_value={"count": 0}),
        read_item=AsyncMock(return_value={"quarantine_id": "q"}),
        approve=AsyncMock(return_value={"approved": True}),
        reject=AsyncMock(return_value={"rejected": True}),
        postpone=AsyncMock(return_value={"postponed": True}),
    )
    app_module.runtime.admin = admin
    auth = {"authorization": "Bearer admin"}

    response = await app_module.dispatch(
        "admin/quarantine/queue",
        request("GET", "/admin/quarantine/queue", headers=auth, query="limit=5&offset=1"),
    )
    assert payload(response) == {"items": []}
    admin.list_queue.assert_awaited_with(5, 1)
    with pytest.raises(HttpError) as invalid_int:
        await app_module.dispatch(
            "admin/quarantine/queue",
            request("GET", "/admin/quarantine/queue", headers=auth, query="limit=x"),
        )
    assert invalid_int.value.code == "invalid_query"
    with pytest.raises(HttpError):
        await app_module.dispatch(
            "admin/quarantine/queue",
            request("GET", "/admin/quarantine/queue", headers=auth, query="limit=0"),
        )

    assert payload(
        await app_module.dispatch(
            "admin/quarantine/stats", request("GET", "/admin/quarantine/stats", headers=auth)
        )
    ) == {"total_items": 0}
    assert payload(
        await app_module.dispatch(
            "admin/quarantine/cleanup",
            request("POST", "/admin/quarantine/cleanup", headers=auth, body={}),
        )
    ) == {"count": 0}
    with pytest.raises(HttpError):
        await app_module.dispatch(
            "admin/quarantine/cleanup",
            request("POST", "/admin/quarantine/cleanup", headers=auth, body=[]),
        )

    assert payload(
        await app_module.dispatch(
            "admin/quarantine/items/q",
            request("GET", "/admin/quarantine/items/q", headers=auth),
        )
    )["quarantine_id"] == "q"
    assert payload(
        await app_module.dispatch(
            "admin/quarantine/items/q/approve",
            request("POST", "/admin/quarantine/items/q/approve", headers=auth, body={}),
        )
    )["approved"] is True
    with pytest.raises(HttpError):
        await app_module.dispatch(
            "admin/quarantine/items/q/approve",
            request("POST", "/admin/quarantine/items/q/approve", headers=auth, body=[]),
        )
    assert payload(
        await app_module.dispatch(
            "admin/quarantine/items/q/reject",
            request("POST", "/admin/quarantine/items/q/reject", headers=auth),
        )
    )["rejected"] is True
    assert payload(
        await app_module.dispatch(
            "admin/quarantine/items/q/postpone",
            request("POST", "/admin/quarantine/items/q/postpone", headers=auth),
        )
    )["postponed"] is True
    response = await app_module.dispatch(
        "admin/nope", request("GET", "/admin/nope", headers=auth)
    )
    assert response.status_code == 404 and payload(response)["error"] == "admin_endpoint_not_found"

    response = await app_module.dispatch(
        "admin/quarantine/stats", request("GET", "/admin/quarantine/stats")
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_lifespan_starts_and_stops_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    start = AsyncMock()
    stop = AsyncMock()
    monkeypatch.setattr(app_module.runtime, "start", start)
    monkeypatch.setattr(app_module.runtime, "stop", stop)
    async with app_module.lifespan(app_module.app):
        start.assert_awaited_once()
    stop.assert_awaited_once()
