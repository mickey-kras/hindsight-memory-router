from __future__ import annotations

import asyncio
import io
import json
import logging
from typing import Any

import httpx
import pytest
from pytest_httpx import HTTPXMock

import memory_router.app as app_module
from memory_router.auth import AuthFailureAuditor
from memory_router.hindsight import HindsightGateway, HindsightGatewayError
from memory_router.logging import configure_logging
from memory_router.observability import RequestIdMiddleware, current_request_id
from tests.request_helpers import request

_SENTINEL = "SENTINEL-secret-header-url-body-query-decrypted-exception"


async def _respond_with_request_id(scope: dict[str, Any], receive: Any, send: Any) -> None:
    del scope, receive
    value = current_request_id()
    assert value is not None
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": value.encode("ascii")})


@pytest.mark.asyncio
async def test_request_id_middleware_preserves_valid_id_and_replaces_invalid() -> None:
    transport = httpx.ASGITransport(app=RequestIdMiddleware(_respond_with_request_id))
    async with httpx.AsyncClient(transport=transport, base_url="http://router") as client:
        response = await client.get("/", headers={"x-request-id": "req-123"})
        assert response.text == "req-123"
        assert response.headers["x-request-id"] == "req-123"

        response = await client.get("/", headers={"x-request-id": "invalid request id"})
        generated = response.headers["x-request-id"]
        assert generated == response.text
        assert len(generated) == 32
        assert generated != "invalid request id"


@pytest.mark.asyncio
async def test_request_id_is_propagated_to_hindsight(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="http://hindsight/health",
        json={"status": "healthy", "database": "connected"},
    )
    gateway = HindsightGateway("http://hindsight", None)

    async def inner(scope: dict[str, Any], receive: Any, send: Any) -> None:
        del scope, receive
        await gateway.health()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    transport = httpx.ASGITransport(app=RequestIdMiddleware(inner))
    async with httpx.AsyncClient(transport=transport, base_url="http://router") as client:
        response = await client.get("/", headers={"x-request-id": "req-upstream"})
        assert response.status_code == 204
        assert response.headers["x-request-id"] == "req-upstream"

    request = httpx_mock.get_request(url="http://hindsight/health")
    assert request is not None
    assert request.headers["x-request-id"] == "req-upstream"
    await gateway.close()


@pytest.mark.asyncio
async def test_unhandled_failure_log_does_not_emit_exception_details(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_detail = "sensitive-request-detail"
    caplog.set_level(logging.ERROR, logger="memory_router.app")

    response = await app_module.unhandled_handler(
        request("POST", f"/private/{_SENTINEL}", headers={"authorization": _SENTINEL}),
        RuntimeError(sensitive_detail),
    )

    assert response.status_code == 500
    assert any(getattr(record, "error_kind", None) == "RuntimeError" for record in caplog.records)
    assert sensitive_detail not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    record = next(record for record in caplog.records if record.msg == "request_failed")
    assert record.operation == "request"  # type: ignore[attr-defined]
    assert record.method == "POST"  # type: ignore[attr-defined]
    assert record.route_class == "unmatched"  # type: ignore[attr-defined]
    assert not hasattr(record, "path")


@pytest.mark.parametrize(
    ("kind", "upstream_status"),
    [
        ("timeout", None),
        ("http", 503),
        ("invalid-response", 200),
        ("network", None),
        ("response-too-large", 200),
    ],
)
@pytest.mark.asyncio
async def test_every_hindsight_failure_kind_has_safe_structured_context(
    kind: str,
    upstream_status: int | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    error = HindsightGatewayError(  # type: ignore[arg-type]
        kind,
        upstream_status=upstream_status,
        operation="recall",
        method="POST",
    )
    error.__cause__ = RuntimeError(_SENTINEL)
    caplog.set_level(logging.WARNING, logger="memory_router.app")

    response = await app_module.http_error_handler(
        request(
            "POST",
            f"/private/{_SENTINEL}?query={_SENTINEL}",
            body={"query": _SENTINEL, "decrypted": _SENTINEL},
            headers={"authorization": f"Bearer {_SENTINEL}"},
        ),
        error,
    )

    assert response.status_code == error.status
    record = next(record for record in caplog.records if record.msg == "hindsight_request_failed")
    assert record.operation == "recall"  # type: ignore[attr-defined]
    assert record.method == "POST"  # type: ignore[attr-defined]
    assert record.error_kind == kind  # type: ignore[attr-defined]
    assert record.route_class == "unmatched"  # type: ignore[attr-defined]
    assert getattr(record, "upstream_status", None) == upstream_status
    assert _SENTINEL not in caplog.text
    assert record.exc_info is None


@pytest.mark.parametrize(
    "kind", ["timeout", "http", "invalid-response", "network", "response-too-large"]
)
@pytest.mark.asyncio
async def test_readiness_failure_kind_is_logged_without_sensitive_details(
    kind: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_module._readiness_log_state = app_module._ReadinessLogState()
    error = HindsightGatewayError(  # type: ignore[arg-type]
        kind,
        upstream_status=503 if kind == "http" else None,
        operation="health",
        method="GET",
    )
    error.__cause__ = RuntimeError(_SENTINEL)
    hindsight = type("Hindsight", (), {"health": AsyncFail(error)})()
    caplog.set_level(logging.WARNING, logger="memory_router.app")

    healthy, response = await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]

    assert (healthy, response) == (False, None)
    record = next(record for record in caplog.records if record.msg == "hindsight_readiness_failed")
    assert record.error_kind == kind  # type: ignore[attr-defined]
    assert record.route_class == "readiness"  # type: ignore[attr-defined]
    assert isinstance(record.duration_ms, float)  # type: ignore[attr-defined]
    assert _SENTINEL not in caplog.text
    assert record.exc_info is None


class AsyncFail:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def __call__(self) -> None:
        raise self.error


@pytest.mark.asyncio
async def test_readiness_logs_failure_once_and_recovery_transition(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_module._readiness_log_state = app_module._ReadinessLogState()
    error = HindsightGatewayError("network", operation="health", method="GET")
    health = AsyncFail(error)
    hindsight = type("Hindsight", (), {"health": health})()
    caplog.set_level(logging.WARNING, logger="memory_router.app")

    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("hindsight_readiness_failed") == 1

    async def recovered() -> dict[str, str]:
        return {"status": "healthy", "database": "connected"}

    hindsight.health = recovered
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("hindsight_readiness_recovered") == 1


def test_runtime_formatter_fail_closed_for_direct_stdlib_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = io.StringIO()
    monkeypatch.setattr("memory_router.logging.sys.stdout", output)
    configure_logging()
    logger = logging.getLogger("memory_router.test")

    logger.warning(
        "safe_event",
        extra={
            "request_id": "req-1",
            "operation": "recall",
            "method": "POST",
            "error_kind": "network",
            "status": 502,
            "duration_ms": 1.25,
            "route_class": "memory",
            "headers": {"authorization": _SENTINEL},
            "url": f"https://example.invalid/{_SENTINEL}",
            "path": f"/private/{_SENTINEL}",
            "body": {"query": _SENTINEL},
            "query": _SENTINEL,
            "memory": _SENTINEL,
            "decrypted": _SENTINEL,
        },
    )

    record = json.loads(output.getvalue())
    assert record["event"] == "safe_event"
    assert record["request_id"] == "req-1"
    assert record["route_class"] == "memory"
    assert _SENTINEL not in output.getvalue()
    assert not (
        {
            "headers",
            "url",
            "path",
            "body",
            "query",
            "memory",
            "decrypted",
            "exception",
        }
        & record.keys()
    )

    logger.error("exception_event", exc_info=RuntimeError(_SENTINEL), stack_info=True)
    exception_record = json.loads(output.getvalue().splitlines()[-1])
    assert _SENTINEL not in output.getvalue()
    assert not ({"exception", "exc_info", "stack_info"} & exception_record.keys())
    logging.basicConfig(handlers=[logging.NullHandler()], force=True)


@pytest.mark.asyncio
async def test_auth_audit_failure_log_does_not_emit_exception_details(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_detail = "sensitive-auth-persistence-detail"

    class FailingStore:
        async def put(self, _: dict[str, Any]) -> None:
            raise RuntimeError(sensitive_detail)

    caplog.set_level(logging.ERROR, logger="memory_router.auth")
    await AuthFailureAuditor(FailingStore()).record("router")

    assert any(getattr(record, "error_kind", None) == "RuntimeError" for record in caplog.records)
    assert sensitive_detail not in caplog.text
    assert all(
        record.exc_info is None for record in caplog.records if record.levelno >= logging.ERROR
    )


@pytest.mark.asyncio
async def test_sweeper_failure_log_does_not_emit_exception_details(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_detail = "sensitive-sweeper-detail"
    sleep_calls = 0

    async def fake_sleep(_: int) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            raise asyncio.CancelledError

    async def fail_recovery(*_: Any) -> None:
        raise RuntimeError(sensitive_detail)

    runtime = app_module.Runtime()
    runtime.repository = object()  # type: ignore[assignment]
    monkeypatch.setattr(app_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(app_module, "recover_interrupted", fail_recovery)
    caplog.set_level(logging.ERROR, logger="memory_router.app")

    with pytest.raises(asyncio.CancelledError):
        await runtime._sweep_loop(1, 0)

    assert any(getattr(record, "error_kind", None) == "RuntimeError" for record in caplog.records)
    assert sensitive_detail not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
