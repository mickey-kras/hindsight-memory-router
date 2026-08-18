from __future__ import annotations

import asyncio
import io
import json
import logging
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

import memory_router.app as app_module
from memory_router.auth import AuthFailureAuditor
from memory_router.hindsight import HindsightGateway, HindsightGatewayError
from memory_router.logging import _ProtocolNoiseFilter, configure_logging, log_event
from memory_router.observability import RequestIdMiddleware, current_request_id
from tests.request_helpers import request

_SENTINEL = "SENTINEL-secret-header-url-body-query-decrypted-exception"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/health", "readiness"),
        ("/health/ready", "readiness"),
        ("/ready", "readiness"),
        ("/health/live", "liveness"),
        ("/version", "version"),
        ("/admin/quarantine/queue", "admin"),
        ("/v1/default/banks/main/memories", "memory"),
        ("/v1/default/banks/main/memories/recall", "memory"),
        ("/v1/default/banks/main/config", "openclaw"),
        ("/v1/default/banks/main/mental-models", "openclaw"),
        ("/private/identifier", "unmatched"),
    ],
)
def test_route_class_uses_bounded_normalized_categories(path: str, expected: str) -> None:
    assert app_module._route_class(request("GET", path)) == expected


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
    assert any(getattr(record, "error_kind", None) == "unexpected" for record in caplog.records)
    assert sensitive_detail not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    record = next(record for record in caplog.records if record.msg == "request_failed")
    assert record.operation == "request"  # type: ignore[attr-defined]
    assert record.request_method == "POST"  # type: ignore[attr-defined]
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
    assert record.upstream_method == "POST"  # type: ignore[attr-defined]
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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module, "_readiness_log_state", app_module._ReadinessLogState())
    error = HindsightGatewayError(  # type: ignore[arg-type]
        kind,
        upstream_status=503 if kind == "http" else None,
        operation="health",
        method="GET",
    )
    error.__cause__ = RuntimeError(_SENTINEL)
    hindsight = type("Hindsight", (), {"health": AsyncFail(error)})()
    caplog.set_level(logging.WARNING, logger="memory_router.app")

    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    healthy, response, _, _ = await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]

    assert (healthy, response) == (False, None)
    record = next(record for record in caplog.records if record.msg == "hindsight_readiness_failed")
    assert record.error_kind == kind  # type: ignore[attr-defined]
    assert record.route_class == "readiness"  # type: ignore[attr-defined]
    assert isinstance(record.operation_duration_ms, float)  # type: ignore[attr-defined]
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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = app_module._ReadinessLogState()
    monkeypatch.setattr(app_module, "_readiness_log_state", state)
    error = HindsightGatewayError("network", operation="health", method="GET")
    health = AsyncFail(error)
    hindsight = type("Hindsight", (), {"health": health})()
    caplog.set_level(logging.INFO, logger="memory_router.app")

    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("hindsight_readiness_failed") == 1

    async def recovered() -> dict[str, str]:
        return {"status": "healthy", "database": "connected"}

    hindsight.health = recovered
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("hindsight_readiness_recovered") == 1
    assert state.last_recovery_log > 0
    assert state.last_failure_log["network"] < state.last_recovery_log

    hindsight.health = health
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("hindsight_readiness_failed") == 2


@pytest.mark.asyncio
async def test_readiness_logs_new_failure_kind_without_waiting(
    caplog: pytest.LogCaptureFixture,
) -> None:
    state = app_module._ReadinessLogState()
    first = HindsightGatewayError("network", operation="health", method="GET")
    second = HindsightGatewayError("timeout", operation="health", method="GET")

    state.record(first, 1.0)
    state.record(first, 1.0)
    state.record(second, 1.0)

    failures = [record for record in caplog.records if record.msg == "hindsight_readiness_failed"]
    assert [record.error_kind for record in failures] == ["network", "timeout"]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_storage_readiness_failure_and_recovery_are_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    repository = type("Repository", (), {"ping": AsyncFail(RuntimeError("database down"))})()

    await app_module._database_health(repository)  # type: ignore[arg-type]
    await app_module._database_health(repository)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("storage_readiness_failed") == 1

    async def recovered() -> None:
        return None

    repository.ping = recovered
    await app_module._database_health(repository)  # type: ignore[arg-type]
    await app_module._database_health(repository)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("storage_readiness_recovered") == 1


@pytest.mark.asyncio
async def test_readiness_serves_stale_cache_while_refresh_lock_is_held() -> None:
    app_module._readiness_cache = (0.0, 200, b'{"status":"healthy"}')
    app_module._readiness_lock = asyncio.Lock()
    await app_module._readiness_lock.acquire()
    try:
        response = await app_module._health_ready_response()
    finally:
        app_module._readiness_lock.release()

    assert response.status_code == 200
    assert response.body == b'{"status":"healthy"}'


@pytest.mark.asyncio
async def test_lifespan_logs_startup_success_and_failure(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = AsyncMock()
    stopped = AsyncMock()
    monkeypatch.setattr(app_module.runtime, "start", started)
    monkeypatch.setattr(app_module.runtime, "stop", stopped)

    async with app_module.lifespan(app_module.app):
        pass
    assert any(record.msg == "application_started" for record in caplog.records)
    stopped.assert_awaited_once()

    caplog.clear()
    started.side_effect = RuntimeError("startup secret")
    with pytest.raises(RuntimeError, match="startup secret"):
        async with app_module.lifespan(app_module.app):
            pass
    record = next(record for record in caplog.records if record.msg == "application_start_failed")
    assert record.error_fingerprint == "RuntimeError"  # type: ignore[attr-defined]
    assert "startup secret" not in caplog.text


def test_log_contract_normalization_throttle_and_suppressed_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("memory_router.test")
    log_event(logger, "warning", "not_registered")
    log_event(logger, "warning", "request_failed", timestamp="unsafe")
    violations = [record for record in caplog.records if record.msg == "logging_contract_violation"]
    assert [record.reason for record in violations] == [  # type: ignore[attr-defined]
        "unregistered-event",
        "reserved-field",
    ]

    for _ in range(2):
        log_event(
            logger,
            "warning",
            "hindsight_request_failed",
            route_class="memory",
            error_kind="network",
            outcome="failed",
            writer_id="w" * 500,
        )
    key = ("hindsight_request_failed", "memory", "network")
    import memory_router.logging as logging_module

    logging_module._last_emitted[key] -= 61
    log_event(
        logger,
        "warning",
        "hindsight_request_failed",
        route_class="memory",
        error_kind="network",
        outcome="failed",
        writer_id="w" * 500,
    )
    records = [record for record in caplog.records if record.msg == "hindsight_request_failed"]
    assert len(records) == 2
    assert records[-1].suppressed == 1  # type: ignore[attr-defined]
    assert len(records[-1].writer_id) == 128  # type: ignore[attr-defined]


def test_protocol_noise_filter_counts_suppressed_records() -> None:
    noise_filter = _ProtocolNoiseFilter()
    first = logging.LogRecord(
        "uvicorn.error", logging.WARNING, "", 0, "Invalid HTTP request received.", (), None
    )
    second = logging.LogRecord(
        "uvicorn.error", logging.WARNING, "", 0, "Invalid HTTP request received.", (), None
    )
    assert noise_filter.filter(first)
    assert not noise_filter.filter(second)
    noise_filter.last -= 61
    third = logging.LogRecord(
        "uvicorn.error", logging.WARNING, "", 0, "Invalid HTTP request received.", (), None
    )
    assert noise_filter.filter(third)
    assert third.suppressed == 1  # type: ignore[attr-defined]


def test_runtime_formatter_fail_closed_for_direct_stdlib_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = io.StringIO()
    monkeypatch.setattr("memory_router.logging.sys.stdout", output)
    application_logger = logging.getLogger("memory_router")
    original_handlers = list(application_logger.handlers)
    original_level = application_logger.level
    original_propagate = application_logger.propagate
    uvicorn_logger = logging.getLogger("uvicorn.error")
    original_uvicorn_handlers = list(uvicorn_logger.handlers)
    original_uvicorn_level = uvicorn_logger.level
    original_uvicorn_propagate = uvicorn_logger.propagate
    try:
        configure_logging()
        logger = logging.getLogger("memory_router.test")
        log_event(
            logger,
            "warning",
            "hindsight_request_failed",
            request_id="req-1",
            operation="recall",
            upstream_method="POST",
            error_kind="network",
            http_status=502,
            operation_duration_ms=1.25,
            route_class="memory",
            headers={"authorization": _SENTINEL},
            url=f"https://example.invalid/{_SENTINEL}",
            path=f"/private/{_SENTINEL}",
            body={"query": _SENTINEL},
            query=_SENTINEL,
            memory=_SENTINEL,
            decrypted=_SENTINEL,
        )

        record = json.loads(output.getvalue())
        assert record["event"] == "hindsight_request_failed"
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

        logger.error("exception_event\n", exc_info=RuntimeError(_SENTINEL), stack_info=True)
        exception_record = json.loads(output.getvalue().splitlines()[-1])
        assert exception_record["event"] == "exception_event"
        assert _SENTINEL not in output.getvalue()
        assert not ({"exception", "exc_info", "stack_info"} & exception_record.keys())
    finally:
        for handler in list(application_logger.handlers):
            if handler not in original_handlers:
                application_logger.removeHandler(handler)
                handler.close()
        application_logger.handlers[:] = original_handlers
        application_logger.setLevel(original_level)
        application_logger.propagate = original_propagate
        uvicorn_logger.handlers[:] = original_uvicorn_handlers
        uvicorn_logger.setLevel(original_uvicorn_level)
        uvicorn_logger.propagate = original_uvicorn_propagate


def test_configure_logging_preserves_root_and_suppresses_http_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = logging.getLogger()
    existing = logging.NullHandler()
    original_handlers = list(root.handlers)
    original_level = root.level
    application_logger = logging.getLogger("memory_router")
    original_application_handlers = list(application_logger.handlers)
    original_application_level = application_logger.level
    original_application_propagate = application_logger.propagate
    uvicorn_logger = logging.getLogger("uvicorn.error")
    original_uvicorn_handlers = list(uvicorn_logger.handlers)
    original_uvicorn_level = uvicorn_logger.level
    original_uvicorn_propagate = uvicorn_logger.propagate
    root.handlers[:] = [existing]
    root.setLevel(logging.WARNING)
    output = io.StringIO()
    monkeypatch.setattr("memory_router.logging.sys.stdout", output)
    try:
        configure_logging()
        assert root.handlers == [existing]
        assert root.level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.WARNING
        assert logging.getLogger("httpcore").level == logging.WARNING
        logging.getLogger("httpx").info("HTTP Request: GET https://example.invalid/%s", _SENTINEL)
        assert _SENTINEL not in output.getvalue()
    finally:
        root.handlers[:] = original_handlers
        root.setLevel(original_level)
        application_logger.handlers[:] = original_application_handlers
        application_logger.setLevel(original_application_level)
        application_logger.propagate = original_application_propagate
        uvicorn_logger.handlers[:] = original_uvicorn_handlers
        uvicorn_logger.setLevel(original_uvicorn_level)
        uvicorn_logger.propagate = original_uvicorn_propagate


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

    assert any(getattr(record, "error_kind", None) == "unexpected" for record in caplog.records)
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

    assert any(getattr(record, "error_kind", None) == "unexpected" for record in caplog.records)
    assert sensitive_detail not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
