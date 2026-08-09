from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
import pytest
from pytest_httpx import HTTPXMock

import memory_router.app as app_module
from memory_router.auth import AuthFailureAuditor
from memory_router.hindsight import HindsightGateway
from memory_router.observability import RequestIdMiddleware, current_request_id


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
    httpx_mock.add_response(url="http://hindsight/health", json={"ok": True})
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
    secret = "sensitive-request-detail"
    caplog.set_level(logging.ERROR, logger="memory_router.app")

    response = await app_module.unhandled_handler(None, RuntimeError(secret))  # type: ignore[arg-type]

    assert response.status_code == 500
    assert "RuntimeError" in caplog.text
    assert secret not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.asyncio
async def test_auth_audit_failure_log_does_not_emit_exception_details(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "sensitive-auth-persistence-detail"

    class FailingStore:
        async def put(self, _: dict[str, Any]) -> None:
            raise RuntimeError(secret)

    caplog.set_level(logging.ERROR, logger="memory_router.auth")
    await AuthFailureAuditor(FailingStore()).record("router")

    assert "RuntimeError" in caplog.text
    assert secret not in caplog.text
    assert all(
        record.exc_info is None for record in caplog.records if record.levelno >= logging.ERROR
    )


@pytest.mark.asyncio
async def test_sweeper_failure_log_does_not_emit_exception_details(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "sensitive-sweeper-detail"
    sleep_calls = 0

    async def fake_sleep(_: int) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            raise asyncio.CancelledError

    async def fail_recovery(*_: Any) -> None:
        raise RuntimeError(secret)

    runtime = app_module.Runtime()
    runtime.repository = object()  # type: ignore[assignment]
    monkeypatch.setattr(app_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(app_module, "recover_interrupted", fail_recovery)
    caplog.set_level(logging.ERROR, logger="memory_router.app")

    with pytest.raises(asyncio.CancelledError):
        await runtime._sweep_loop(1, 0)

    assert "RuntimeError" in caplog.text
    assert secret not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
