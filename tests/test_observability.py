from __future__ import annotations

from typing import Any

import httpx
import pytest
from pytest_httpx import HTTPXMock

from memory_router.hindsight import HindsightGateway
from memory_router.observability import RequestIdMiddleware, current_request_id


async def _respond_with_request_id(
    scope: dict[str, Any], receive: Any, send: Any
) -> None:
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
