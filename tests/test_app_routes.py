from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from memory_router import app as app_module
from memory_router.errors import HttpError
from memory_router.hindsight import HindsightGatewayError
from tests.request_helpers import request


def payload(response: object) -> object:
    return json.loads(response.body)  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def runtime_state() -> None:
    app_module._readiness_log_state = app_module._ReadinessLogState()
    app_module._storage_readiness_log_state = app_module._ReadinessLogState(
        "storage_readiness_failed", "storage_readiness_recovered", "storage_health"
    )
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
    app_module.runtime.auth_limiter = SimpleNamespace(consume_many=AsyncMock())
    app_module.runtime.auth_failure_max = 120
    app_module.runtime.auth_failure_window = 60_000
    app_module.runtime.auditor = SimpleNamespace(log_failure=Mock(), persist=AsyncMock())


@pytest.mark.asyncio
async def test_health_endpoints_and_exception_handlers(caplog: pytest.LogCaptureFixture) -> None:
    repository = SimpleNamespace(ping=AsyncMock())
    upstream_health = {
        "status": "healthy",
        "database": "connected",
        "db_acquire_ms": 0.4,
        "db_pool_waiting": 0,
    }
    hindsight = SimpleNamespace(health=AsyncMock(return_value=upstream_health))
    app_module.runtime.repository = repository
    app_module.runtime.hindsight = hindsight

    live = await app_module.health_live()
    assert live["status"] == "alive"
    assert isinstance(live["version"], str) and live["version"]
    assert isinstance(live["uptime_seconds"], float) and live["uptime_seconds"] >= 0
    repository.ping.assert_not_awaited()
    hindsight.health.assert_not_awaited()

    response = await app_module.health_ready()
    assert response.status_code == 200
    assert payload(response) == upstream_health
    repository.ping.assert_awaited_once()
    hindsight.health.assert_awaited_once()

    response = await app_module.ready()
    assert response.status_code == 200
    assert payload(response) == upstream_health
    cached = app_module._readiness_cache
    assert cached is not None and isinstance(cached[2], bytes)
    assert app_module._readiness_cache is cached

    repository.ping.side_effect = RuntimeError("database down")
    hindsight.health.reset_mock()
    app_module._readiness_cache = None
    response = await app_module.health_ready()
    assert response.status_code == 503
    assert payload(response) == {"status": "unhealthy"}
    hindsight.health.assert_awaited_once()

    repository.ping.side_effect = None
    hindsight.health.side_effect = HindsightGatewayError(
        "network", operation="health", method="GET"
    )
    app_module._readiness_cache = None
    response = await app_module.health_ready()
    assert response.status_code == 503
    assert payload(response) == {"status": "unhealthy"}

    response = await app_module.http_error_handler(
        request("GET", "/"), HttpError(429, "limited", "slow", {"retry-after": "2"})
    )
    assert response.status_code == 429 and response.headers["retry-after"] == "2"
    gateway = HindsightGatewayError("network", operation="recall", method="POST")
    response = await app_module.http_error_handler(request("GET", "/"), gateway)
    assert response.status_code == 502 and payload(response)["error"] == "hindsight_unavailable"
    assert "hindsight_request_failed" in caplog.text
    caplog.clear()
    response = await app_module.unhandled_handler(request("GET", "/"), RuntimeError("failure"))
    assert response.status_code == 500 and payload(response) == {"error": "internal error"}
    assert "request_failed" in caplog.text


@pytest.mark.asyncio
async def test_json_body_bounds_empty_body_and_invalid_json() -> None:
    app_module.runtime.max_body_bytes = 3
    with pytest.raises(HttpError) as declared:
        await app_module._json_body(
            request("POST", "/", body=b"{}", headers={"content-length": "4"})
        )
    assert declared.value.status == 413
    assert declared.value.code == "payload_too_large"
    with pytest.raises(HttpError) as actual:
        await app_module._json_body(request("POST", "/", body=b"1234"))
    assert actual.value.code == "payload_too_large"
    app_module.runtime.max_body_bytes = 100
    with pytest.raises(HttpError) as invalid:
        await app_module._json_body(request("POST", "/", body=b"{"))
    assert invalid.value.code == "invalid_json"
    assert await app_module._json_body(request("POST", "/")) == {}
    assert await app_module._json_body(request("POST", "/", body={"x": 1})) == {"x": 1}


@pytest.mark.asyncio
async def test_router_and_admin_auth_failures_are_audited() -> None:
    app_module.runtime.allow_anonymous = False
    auth_value = "route" + "r"
    app_module.runtime.router_token = auth_value
    assert not await app_module._router_auth(request("GET", "/version"))
    app_module.runtime.auditor.log_failure.assert_called_with("version")
    app_module.runtime.auditor.persist.assert_awaited_with("router", "version")
    assert await app_module._router_auth(
        request("GET", "/version", headers={"authorization": f"Bearer {auth_value}"})
    )
    assert not await app_module._admin_auth(request("GET", "/admin/quarantine/stats"), "read")
    app_module.runtime.auditor.log_failure.assert_called_with("admin")
    app_module.runtime.auditor.persist.assert_awaited_with("admin", "admin")
    assert await app_module._admin_auth(
        request(
            "GET",
            "/admin/quarantine/stats",
            headers={"authorization": "Bearer admin"},
        ),
        "read",
    )


@pytest.mark.asyncio
async def test_auth_failure_is_logged_but_not_persisted_after_limiter_rejects() -> None:
    app_module.runtime.allow_anonymous = False
    app_module.runtime.router_token = "router-token"  # noqa: S105 - synthetic test credential
    app_module.runtime.auth_limiter.consume_many.side_effect = HttpError(429, "limited", "limited")

    with pytest.raises(HttpError) as limited:
        await app_module._router_auth(request("GET", "/version"))

    assert limited.value.code == "auth_rate_limited"
    app_module.runtime.auditor.log_failure.assert_called_once_with("version")
    app_module.runtime.auditor.persist.assert_not_awaited()


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
    limits = SimpleNamespace(assert_retain_bounds=Mock(), assert_recall_bounds=Mock())
    policy = SimpleNamespace(
        limits=limits,
        retain=AsyncMock(return_value={"retained": True}),
        recall=AsyncMock(return_value={"results": []}),
        deny_endpoint=AsyncMock(return_value={"error": "endpoint_not_allowed"}),
    )
    version_response = {
        "api_version": "0.9.0",
        "features": {
            "observations": True,
            "mcp": True,
            "worker": True,
            "bank_config_api": True,
            "bank_llm_health": True,
            "file_upload_api": True,
            "document_export_api": True,
            "document_import_api": True,
            "audit_log": True,
            "llm_trace": True,
            "store_document_text": True,
        },
    }
    hindsight = SimpleNamespace(version=AsyncMock(return_value=version_response))
    app_module.runtime.policy = policy
    app_module.runtime.hindsight = hindsight

    app_module.runtime.allow_anonymous = False
    auth_value = "route" + "r"
    app_module.runtime.router_token = auth_value
    response = await app_module.dispatch("version", request("GET", "/version"))
    assert response.status_code == 200 and payload(response) == version_response
    hindsight.version.assert_awaited_once()

    app_module.runtime.allow_anonymous = True
    app_module.runtime.router_token = None
    response = await app_module.dispatch(
        "v1/default/banks/main/memories",
        request("POST", "/v1/default/banks/main/memories", body={"items": [{"content": "ok"}]}),
    )
    assert payload(response) == {"retained": True}
    limits.assert_retain_bounds.assert_called_once()
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
    limits.assert_recall_bounds.assert_called_once()
    policy.recall.assert_awaited_once()

    response = await app_module.dispatch("missing", request("GET", "/missing"))
    assert response.status_code == 404 and payload(response)["error"] == "endpoint_not_allowed"

    app_module.runtime.allow_anonymous = False
    response = await app_module.dispatch(
        "v1/default/banks/main/memories",
        request("POST", "/v1/default/banks/main/memories", body={"items": [{"content": "ok"}]}),
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_encoded_writer_segment_preserves_routing() -> None:
    limits = SimpleNamespace(assert_retain_bounds=Mock(), assert_recall_bounds=Mock())
    policy = SimpleNamespace(
        limits=limits,
        retain=AsyncMock(return_value={"retained": True}),
        recall=AsyncMock(return_value={"results": []}),
        deny_endpoint=AsyncMock(return_value={"error": "endpoint_not_allowed"}),
    )
    app_module.runtime.policy = policy

    response = await app_module.dispatch(
        "unused",
        request(
            "POST",
            "/v1/default/banks/team%2Fwriter/memories",
            body={"items": [{"content": "ok"}]},
        ),
    )
    assert response.status_code == 200
    policy.retain.assert_awaited_once()
    assert policy.retain.await_args.args[0] == "team/writer"


@pytest.mark.asyncio
async def test_malformed_percent_encoding_falls_through_after_auth() -> None:
    policy = SimpleNamespace(
        deny_endpoint=AsyncMock(return_value={"error": "endpoint_not_allowed"})
    )
    app_module.runtime.policy = policy
    response = await app_module.dispatch("unused", request("GET", "/bad%ZZ"))
    assert response.status_code == 404
    assert payload(response)["error"] == "endpoint_not_allowed"
    policy.deny_endpoint.assert_awaited_with("GET", "/bad%ZZ")


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
    with pytest.raises(HttpError) as duplicate:
        await app_module.dispatch(
            "admin/quarantine/queue",
            request(
                "GET",
                "/admin/quarantine/queue",
                headers=auth,
                query="limit=1&limit=2",
            ),
        )
    assert duplicate.value.code == "invalid_query"

    assert payload(
        await app_module.dispatch(
            "admin/quarantine/stats", request("GET", "/admin/quarantine/stats", headers=auth)
        )
    ) == {"total_items": 0}
    assert payload(
        await app_module.dispatch(
            "admin/quarantine/cleanup",
            request("POST", "/admin/quarantine/cleanup", headers=auth),
        )
    ) == {"count": 0}
    admin.cleanup.assert_awaited_with({})
    with pytest.raises(HttpError):
        await app_module.dispatch(
            "admin/quarantine/cleanup",
            request("POST", "/admin/quarantine/cleanup", headers=auth, body=[]),
        )

    assert (
        payload(
            await app_module.dispatch(
                "admin/quarantine/items/q",
                request("GET", "/admin/quarantine/items/q", headers=auth),
            )
        )["quarantine_id"]
        == "q"
    )
    assert (
        payload(
            await app_module.dispatch(
                "admin/quarantine/items/q/approve",
                request("POST", "/admin/quarantine/items/q/approve", headers=auth, body={}),
            )
        )["approved"]
        is True
    )
    with pytest.raises(HttpError):
        await app_module.dispatch(
            "admin/quarantine/items/q/approve",
            request("POST", "/admin/quarantine/items/q/approve", headers=auth, body=[]),
        )
    assert (
        payload(
            await app_module.dispatch(
                "admin/quarantine/items/q/reject",
                request("POST", "/admin/quarantine/items/q/reject", headers=auth),
            )
        )["rejected"]
        is True
    )
    assert (
        payload(
            await app_module.dispatch(
                "admin/quarantine/items/q/postpone",
                request("POST", "/admin/quarantine/items/q/postpone", headers=auth),
            )
        )["postponed"]
        is True
    )
    response = await app_module.dispatch("admin/nope", request("GET", "/admin/nope", headers=auth))
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
