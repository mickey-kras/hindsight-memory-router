from __future__ import annotations

import asyncio
import io
import json
import logging
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

import memory_router.app as app_module
from memory_router.auth import AuthFailureAuditor
from memory_router.hindsight import HindsightGateway, HindsightGatewayError
from memory_router.logging import (
    LOG_THROTTLE_INTERVAL_SECONDS,
    _ProtocolNoiseFilter,
    configure_logging,
    error_fingerprint,
    log_event,
    reset_log_state,
)
from memory_router.observability import RequestIdMiddleware, current_request_id
from memory_router.openclaw import OpenClawFacade
from memory_router.policy import RouterPolicy
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
    reset_log_state()
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("hindsight_readiness_recovered") == 1

    hindsight.health = health
    reset_log_state()
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("hindsight_readiness_failed") == 2

    hindsight.health = recovered
    reset_log_state()
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    await app_module._hindsight_health(hindsight)  # type: ignore[arg-type]
    assert [record.msg for record in caplog.records].count("hindsight_readiness_recovered") == 2


def test_readiness_debounce_ignores_alternating_observations(
    caplog: pytest.LogCaptureFixture,
) -> None:
    state = app_module._ReadinessLogState()
    failure = HindsightGatewayError("network", operation="health", method="GET")

    state.record(failure, 1.0)
    state.record(None, 1.0)
    state.record(failure, 1.0)
    state.record(None, 1.0)

    assert not any("readiness_" in str(record.msg) for record in caplog.records)


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
async def test_storage_readiness_timeout_is_recorded(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def hangs() -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(app_module, "_DEPENDENCY_PROBE_TIMEOUT_SECONDS", 0.001)
    repository = SimpleNamespace(ping=hangs)

    await app_module._database_health(repository)  # type: ignore[arg-type]
    await app_module._database_health(repository)  # type: ignore[arg-type]

    record = next(record for record in caplog.records if record.msg == "storage_readiness_failed")
    assert record.error_kind == "timeout"  # type: ignore[attr-defined]
    assert record.operation_duration_ms >= 1.0  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_readiness_serves_stale_cache_while_refresh_lock_is_held() -> None:
    app_module._readiness_cache = (
        time.monotonic() - app_module._READINESS_CACHE_SECONDS - 0.1,
        200,
        b'{"status":"healthy"}',
    )
    app_module._readiness_lock = asyncio.Lock()
    await app_module._readiness_lock.acquire()
    try:
        response = await app_module._health_ready_response()
    finally:
        app_module._readiness_lock.release()

    assert response.status_code == 200
    assert response.body == b'{"status":"healthy"}'


@pytest.mark.asyncio
async def test_readiness_fails_closed_when_stale_cache_exceeds_bound() -> None:
    app_module._readiness_cache = (
        time.monotonic() - app_module._CACHE_MAX_STALENESS_SECONDS - 0.1,
        200,
        b'{"status":"healthy"}',
    )
    app_module._readiness_lock = asyncio.Lock()
    await app_module._readiness_lock.acquire()
    try:
        response = await app_module._health_ready_response()
    finally:
        app_module._readiness_lock.release()

    assert response.status_code == 503
    assert json.loads(response.body) == {"status": "unhealthy"}


@pytest.mark.asyncio
async def test_readiness_cold_refresh_returns_503_instead_of_queueing() -> None:
    app_module._readiness_lock = asyncio.Lock()
    await app_module._readiness_lock.acquire()
    try:
        response = await app_module._health_ready_response()
    finally:
        app_module._readiness_lock.release()

    assert response.status_code == 503
    assert json.loads(response.body) == {"status": "unhealthy"}


@pytest.mark.asyncio
async def test_readiness_ttl_expiry_refetches_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ping = AsyncMock()
    health = AsyncMock(return_value={"status": "healthy", "database": "connected"})
    monkeypatch.setattr(app_module.runtime, "repository", SimpleNamespace(ping=ping))
    monkeypatch.setattr(app_module.runtime, "hindsight", SimpleNamespace(health=health))
    app_module._readiness_cache = (
        time.monotonic() - app_module._READINESS_CACHE_SECONDS - 0.1,
        503,
        b'{"status":"unhealthy"}',
    )

    response = await app_module._health_ready_response()

    assert response.status_code == 200
    ping.assert_awaited_once()
    health.assert_awaited_once()


@pytest.mark.asyncio
async def test_readiness_refresh_timeout_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    started = asyncio.Event()

    async def hangs() -> None:
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(app_module.runtime, "repository", SimpleNamespace(ping=hangs))
    monkeypatch.setattr(app_module.runtime, "hindsight", SimpleNamespace(health=hangs))
    monkeypatch.setattr(app_module, "_REFRESH_TIMEOUT_SECONDS", 0.001)

    response = await app_module._health_ready_response()

    assert started.is_set()
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_uninitialized_readiness_does_not_emit_storage_transitions(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module.runtime, "repository", None)
    monkeypatch.setattr(app_module.runtime, "hindsight", None)

    for _ in range(2):
        app_module._readiness_cache = None
        response = await app_module._health_ready_response()
        assert response.status_code == 503

    monkeypatch.setattr(app_module.runtime, "repository", SimpleNamespace(ping=AsyncMock()))
    monkeypatch.setattr(
        app_module.runtime,
        "hindsight",
        SimpleNamespace(
            health=AsyncMock(return_value={"status": "healthy", "database": "connected"})
        ),
    )
    for _ in range(2):
        app_module._readiness_cache = None
        response = await app_module._health_ready_response()
        assert response.status_code == 200

    assert not any(record.msg.startswith("storage_readiness_") for record in caplog.records)


@pytest.mark.asyncio
async def test_version_refresh_fails_fast_for_concurrent_cold_request_and_refetches_after_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def load_version() -> dict[str, Any]:
        started.set()
        await release.wait()
        return {"api_version": "0.9.0", "features": {}}

    version = AsyncMock(side_effect=load_version)
    monkeypatch.setattr(app_module.runtime, "hindsight", SimpleNamespace(version=version))

    first_task = asyncio.create_task(app_module._version_response())
    await started.wait()
    second_task = asyncio.create_task(app_module._version_response())
    await asyncio.sleep(0)
    release.set()
    first, second = await asyncio.gather(first_task, second_task)
    assert first.status_code == 200
    assert second.status_code == 503
    version.assert_awaited_once()

    assert app_module._version_cache is not None
    app_module._version_cache = (
        time.monotonic() - app_module._READINESS_CACHE_SECONDS - 0.1,
        app_module._version_cache[1],
        app_module._version_cache[2],
    )
    await app_module._version_response()
    assert version.await_count == 2


@pytest.mark.parametrize(
    ("age", "expected_status"),
    [
        (app_module._READINESS_CACHE_SECONDS + 0.1, 200),
        (app_module._CACHE_MAX_STALENESS_SECONDS + 0.1, 503),
    ],
)
@pytest.mark.asyncio
async def test_version_stale_response_is_bounded(age: float, expected_status: int) -> None:
    app_module._version_cache = (time.monotonic() - age, 200, b'{"api_version":"cached"}')
    app_module._version_lock = asyncio.Lock()
    await app_module._version_lock.acquire()
    try:
        response = await app_module._version_response()
    finally:
        app_module._version_lock.release()

    assert response.status_code == expected_status


@pytest.mark.asyncio
async def test_version_refresh_timeout_is_cached_and_logged(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def hangs() -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(app_module.runtime, "hindsight", SimpleNamespace(version=hangs))
    monkeypatch.setattr(app_module, "_REFRESH_TIMEOUT_SECONDS", 0.001)

    response = await app_module._version_response()
    cached = await app_module._version_response()

    assert response.status_code == 504
    assert cached.status_code == 504
    assert any(
        record.msg == "hindsight_request_failed" and record.error_kind == "timeout"  # type: ignore[attr-defined]
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_version_failure_does_not_queue_or_amplify_concurrent_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def fail_version() -> None:
        started.set()
        await release.wait()
        raise HindsightGatewayError("network", operation="version", method="GET")

    version = AsyncMock(side_effect=fail_version)
    monkeypatch.setattr(app_module.runtime, "hindsight", SimpleNamespace(version=version))

    first_task = asyncio.create_task(app_module._version_response())
    await started.wait()
    second = await app_module._version_response()
    release.set()
    first = await first_task
    cached = await app_module._version_response()

    assert [first.status_code, second.status_code, cached.status_code] == [502, 503, 502]
    version.assert_awaited_once()


@pytest.mark.asyncio
async def test_version_without_initialized_gateway_fails_closed() -> None:
    app_module.runtime.hindsight = None

    response = await app_module._version_response()

    assert response.status_code == 503


def test_runtime_message_reason_mapping() -> None:
    import memory_router.logging as logging_module

    cases = {
        "Started server process [1]": "server-started",
        "Uvicorn running on http://0.0.0.0:8890 (Press CTRL+C to quit)": "server-running",
        "Waiting for application startup.": "application-startup",
        "Application startup failed. Exiting.": "application-startup",
        "Shutting down": "server-stopping",
        "Waiting for application shutdown.": "application-shutdown",
        "Finished server process [1]": "server-finished",
        "Invalid HTTP request received.": "http-protocol-error",
        "Unsupported upgrade request.": "http-protocol-error",
        "No supported WebSocket library detected. Please use pip install 'uvicorn[standard]'": "http-protocol-error",
        "Exception in ASGI application": "asgi-application-error",
        "Unclassified runtime warning": "runtime-other",
    }
    for message, expected in cases.items():
        record = logging.LogRecord("uvicorn.error", logging.INFO, "", 0, message, (), None)
        event = logging_module._normalize_foreign_event(
            logging.getLogger("uvicorn.error"),
            "info",
            {"event": message, "logger": "uvicorn.error", "_record": record},
        )
        assert event["event"] == "runtime_message"
        assert event["reason"] == expected


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("quarantine_capacity_exceeded", "capacity"),
        ("quarantine_writer_capacity_exceeded", "capacity"),
        ("quarantine_rate_limited", "rate-limit"),
        ("quarantine_item_too_large", "payload-too-large"),
        ("quarantine_request_in_review", "conflict"),
        ("quarantine_item_in_review", "conflict"),
    ],
)
def test_log_degradation_maps_code_and_preserves_writer(
    code: str,
    expected: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    RouterPolicy._log_degradation(
        "quarantine_write_unavailable",
        {"code": code, "status": 429, "writer_id": "writer-1"},
    )

    record = caplog.records[-1]
    assert record.error_kind == expected  # type: ignore[attr-defined]
    assert record.writer_id == "writer-1"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("event", "expected_level"),
    [
        ("bank_unavailable", logging.WARNING),
        ("quarantine_placeholder_unavailable", logging.WARNING),
        ("recall_supplemental_audit_unavailable", logging.ERROR),
    ],
)
def test_degradation_catalog_events_are_emitted(
    event: str, expected_level: int, caplog: pytest.LogCaptureFixture
) -> None:
    RouterPolicy._log_degradation(
        event,
        {"error_kind": "storage", "status": 507, "writer_id": "writer-1"},
    )

    record = next(record for record in caplog.records if record.msg == event)
    assert record.levelno == expected_level


@pytest.mark.asyncio
async def test_openclaw_security_audit_failure_event_is_emitted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    policy = SimpleNamespace(
        _quarantine=AsyncMock(side_effect=RuntimeError("secret audit failure"))
    )

    await OpenClawFacade(policy)._audit(  # noqa: SLF001 - event-path regression coverage
        "writer-1", "openclaw_unknown_writer", {"safe": True}, None
    )

    record = next(
        record for record in caplog.records if record.msg == "openclaw_security_audit_failed"
    )
    assert record.levelno == logging.ERROR
    assert record.reason == "openclaw-unknown-writer"  # type: ignore[attr-defined]
    assert "secret audit failure" not in caplog.text


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


@pytest.mark.asyncio
async def test_lifespan_logs_shutdown_failure_and_preserves_primary_error(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module.runtime, "start", AsyncMock())
    monkeypatch.setattr(
        app_module.runtime, "stop", AsyncMock(side_effect=RuntimeError("shutdown secret"))
    )

    with pytest.raises(ValueError, match="primary"):
        async with app_module.lifespan(app_module.app):
            raise ValueError("primary")

    record = next(record for record in caplog.records if record.msg == "application_stop_failed")
    assert record.error_fingerprint == "RuntimeError"  # type: ignore[attr-defined]
    assert "shutdown secret" not in caplog.text


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
    assert all(record.error_fingerprint.startswith("site:") for record in violations)  # type: ignore[attr-defined]

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

    logging_module._last_emitted[key] -= LOG_THROTTLE_INTERVAL_SECONDS + 1
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

    log_event(
        logger,
        "warning",
        "configuration_warning",
        error_kind={},
        outcome=[],
        route_class={"unbounded": "value"},
    )
    normalized = caplog.records[-1]
    assert normalized.error_kind == "unexpected"  # type: ignore[attr-defined]
    assert normalized.outcome == "failed"  # type: ignore[attr-defined]
    assert normalized.route_class == "unmatched"  # type: ignore[attr-defined]


def test_error_fingerprint_site_branch_and_invalid_fingerprint_drop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class PrivateFailure(Exception):
        pass

    try:
        raise PrivateFailure(_SENTINEL)
    except PrivateFailure as exc:
        assert error_fingerprint(exc).startswith("site:")

    log_event(
        logging.getLogger("memory_router.test"),
        "warning",
        "configuration_warning",
        error_fingerprint="site:invalid",
    )
    assert not hasattr(caplog.records[-1], "error_fingerprint")


def test_error_fingerprint_is_computed_only_after_throttle(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del caplog
    calls = 0

    def fingerprint(_: BaseException) -> str:
        nonlocal calls
        calls += 1
        return "RuntimeError"

    monkeypatch.setattr("memory_router.logging.error_fingerprint", fingerprint)
    logger = logging.getLogger("memory_router.test")
    for _ in range(2):
        log_event(
            logger,
            "warning",
            "request_failed",
            error=RuntimeError(),
            route_class="memory",
            error_kind="unexpected",
        )
    assert calls == 1


def test_log_event_rejects_invalid_error_without_raising(
    caplog: pytest.LogCaptureFixture,
) -> None:
    log_event(
        logging.getLogger("memory_router.test"),
        "error",
        "request_failed",
        error=42,
        route_class="memory",
        error_kind="unexpected",
    )

    record = caplog.records[-1]
    assert record.msg == "request_failed"
    assert not hasattr(record, "error_fingerprint")


def test_log_event_sanitizes_hostile_fields_and_non_finite_numbers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class BrokenText:
        def __str__(self) -> str:
            raise RuntimeError("secret")

    log_event(
        logging.getLogger("memory_router.test"),
        "warning",
        "configuration_warning",
        request_id=BrokenText(),
        operation="x" * 500,
        request_duration_ms=float("nan"),
        http_status={"circular": None},
    )

    record = caplog.records[-1]
    assert record.request_id == "unavailable"  # type: ignore[attr-defined]
    assert not hasattr(record, "operation")
    assert not hasattr(record, "request_duration_ms")
    assert not hasattr(record, "http_status")


def test_throttles_emit_first_event_before_sixty_seconds_of_uptime(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("memory_router.logging.time.monotonic", lambda: 0.1)
    log_event(
        logging.getLogger("memory_router.test"),
        "warning",
        "request_failed",
        route_class="memory",
        error_kind="unexpected",
    )
    assert caplog.records[-1].msg == "request_failed"

    noise_filter = _ProtocolNoiseFilter()
    record = logging.LogRecord(
        "uvicorn.error", logging.WARNING, "", 0, "Invalid HTTP request received.", (), None
    )
    assert noise_filter.filter(record)


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
    assert noise_filter.last is not None
    noise_filter.last -= LOG_THROTTLE_INTERVAL_SECONDS + 1
    third = logging.LogRecord(
        "uvicorn.error", logging.WARNING, "", 0, "Invalid HTTP request received.", (), None
    )
    assert noise_filter.filter(third)
    assert third.suppressed == 1  # type: ignore[attr-defined]


def test_protocol_noise_filter_never_raises_on_bad_format_args() -> None:
    noise_filter = _ProtocolNoiseFilter()
    record = logging.LogRecord("uvicorn.error", logging.WARNING, "", 0, "%s %s", ("one",), None)

    assert not noise_filter.filter(record)


def test_runtime_noise_filter_throttles_asgi_errors() -> None:
    noise_filter = _ProtocolNoiseFilter()
    first = logging.LogRecord(
        "uvicorn.error", logging.ERROR, "", 0, "Exception in ASGI application", (), None
    )
    second = logging.LogRecord(
        "uvicorn.error", logging.ERROR, "", 0, "Exception in ASGI application", (), None
    )

    assert noise_filter.filter(first)
    assert not noise_filter.filter(second)


@pytest.mark.parametrize(
    "message",
    [
        "Unsupported upgrade request.",
        "No supported WebSocket library detected. Please use pip install 'uvicorn[standard]'",
    ],
)
def test_protocol_noise_filter_throttles_unsupported_upgrade(message: str) -> None:
    noise_filter = _ProtocolNoiseFilter()
    first = logging.LogRecord("uvicorn.error", logging.WARNING, "", 0, message, (), None)
    second = logging.LogRecord("uvicorn.error", logging.WARNING, "", 0, message, (), None)
    assert noise_filter.filter(first)
    assert not noise_filter.filter(second)


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
    original_uvicorn_filters = list(uvicorn_logger.filters)
    original_uvicorn_level = uvicorn_logger.level
    original_uvicorn_propagate = uvicorn_logger.propagate
    original_uvicorn_disabled = uvicorn_logger.disabled
    access_logger = logging.getLogger("uvicorn.access")
    original_access_disabled = access_logger.disabled
    original_last_resort = logging.lastResort
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
        assert exception_record["event"] == "logging_contract_violation"
        assert exception_record["reason"] == "direct-stdlib-log"
        assert exception_record["error_fingerprint"].startswith("site:")
        assert _SENTINEL not in output.getvalue()
        assert not ({"exception", "exc_info", "stack_info"} & exception_record.keys())

        logger.error(
            "forged %s",
            _SENTINEL,
            extra={
                "_memory_router_event": True,
                "writer_id": "w" * 500,
                "route_class": _SENTINEL,
                "request_id": _SENTINEL,
            },
        )
        forged_record = json.loads(output.getvalue().splitlines()[-1])
        assert forged_record["event"] == "logging_contract_violation"
        assert forged_record["reason"] == "direct-stdlib-log"
        assert _SENTINEL not in output.getvalue()
        assert "writer_id" not in forged_record
        assert "request_id" not in forged_record
    finally:
        for handler in list(application_logger.handlers):
            if handler not in original_handlers:
                application_logger.removeHandler(handler)
                handler.close()
        application_logger.handlers[:] = original_handlers
        application_logger.setLevel(original_level)
        application_logger.propagate = original_propagate
        uvicorn_logger.handlers[:] = original_uvicorn_handlers
        uvicorn_logger.filters[:] = original_uvicorn_filters
        uvicorn_logger.setLevel(original_uvicorn_level)
        uvicorn_logger.propagate = original_uvicorn_propagate
        uvicorn_logger.disabled = original_uvicorn_disabled
        access_logger.disabled = original_access_disabled
        logging.lastResort = original_last_resort


def test_configure_logging_preserves_root_and_suppresses_http_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = logging.getLogger()
    captured: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    existing = CaptureHandler()
    original_handlers = list(root.handlers)
    original_level = root.level
    application_logger = logging.getLogger("memory_router")
    original_application_handlers = list(application_logger.handlers)
    original_application_level = application_logger.level
    original_application_propagate = application_logger.propagate
    uvicorn_logger = logging.getLogger("uvicorn.error")
    original_uvicorn_handlers = list(uvicorn_logger.handlers)
    original_uvicorn_filters = list(uvicorn_logger.filters)
    original_uvicorn_level = uvicorn_logger.level
    original_uvicorn_propagate = uvicorn_logger.propagate
    original_uvicorn_disabled = uvicorn_logger.disabled
    access_logger = logging.getLogger("uvicorn.access")
    original_access_disabled = access_logger.disabled
    httpx_logger = logging.getLogger("httpx")
    httpcore_logger = logging.getLogger("httpcore")
    original_httpx_level = httpx_logger.level
    original_httpcore_level = httpcore_logger.level
    original_last_resort = logging.lastResort
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
        assert any(
            getattr(filter_, "_memory_router_runtime_noise", False)
            for filter_ in uvicorn_logger.filters
        )
        httpx_logger.info("HTTP Request: GET https://example.invalid/%s", _SENTINEL)
        assert captured == []
        assert _SENTINEL not in output.getvalue()
    finally:
        root.handlers[:] = original_handlers
        root.setLevel(original_level)
        application_logger.handlers[:] = original_application_handlers
        application_logger.setLevel(original_application_level)
        application_logger.propagate = original_application_propagate
        uvicorn_logger.handlers[:] = original_uvicorn_handlers
        uvicorn_logger.filters[:] = original_uvicorn_filters
        uvicorn_logger.setLevel(original_uvicorn_level)
        uvicorn_logger.propagate = original_uvicorn_propagate
        uvicorn_logger.disabled = original_uvicorn_disabled
        access_logger.disabled = original_access_disabled
        httpx_logger.setLevel(original_httpx_level)
        httpcore_logger.setLevel(original_httpcore_level)
        logging.lastResort = original_last_resort


def test_last_resort_handler_enforces_json_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr("memory_router.logging.sys.stdout", output)
    root = logging.getLogger()
    logger = logging.getLogger("asyncio.unhandled")
    application_logger = logging.getLogger("memory_router")
    uvicorn_logger = logging.getLogger("uvicorn.error")
    access_logger = logging.getLogger("uvicorn.access")
    original_root_handlers = list(root.handlers)
    original_logger_handlers = list(logger.handlers)
    original_logger_propagate = logger.propagate
    original_application_handlers = list(application_logger.handlers)
    original_application_level = application_logger.level
    original_application_propagate = application_logger.propagate
    original_uvicorn_handlers = list(uvicorn_logger.handlers)
    original_uvicorn_filters = list(uvicorn_logger.filters)
    original_uvicorn_level = uvicorn_logger.level
    original_uvicorn_propagate = uvicorn_logger.propagate
    original_uvicorn_disabled = uvicorn_logger.disabled
    original_access_disabled = access_logger.disabled
    original_last_resort = logging.lastResort
    try:
        root.handlers[:] = []
        logger.handlers[:] = []
        logger.propagate = True
        configure_logging()
        logger.error("task failed at %s", _SENTINEL)

        record = json.loads(output.getvalue())
        assert record["event"] == "runtime_message"
        assert record["reason"] == "runtime-other"
        assert _SENTINEL not in output.getvalue()
    finally:
        root.handlers[:] = original_root_handlers
        logger.handlers[:] = original_logger_handlers
        logger.propagate = original_logger_propagate
        application_logger.handlers[:] = original_application_handlers
        application_logger.setLevel(original_application_level)
        application_logger.propagate = original_application_propagate
        uvicorn_logger.handlers[:] = original_uvicorn_handlers
        uvicorn_logger.filters[:] = original_uvicorn_filters
        uvicorn_logger.setLevel(original_uvicorn_level)
        uvicorn_logger.propagate = original_uvicorn_propagate
        uvicorn_logger.disabled = original_uvicorn_disabled
        access_logger.disabled = original_access_disabled
        logging.lastResort = original_last_resort


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
