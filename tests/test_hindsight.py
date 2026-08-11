from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest

from memory_router.hindsight import (
    MAX_HINDSIGHT_JSON_DEPTH,
    HindsightGateway,
    HindsightGatewayError,
)


@pytest.mark.asyncio
async def test_health_validates_contract_and_preserves_upstream_response() -> None:
    response = {
        "status": "healthy",
        "database": "connected",
        "db_acquire_ms": 0.4,
        "db_pool_waiting": 0,
    }
    gateway = HindsightGateway("http://hindsight", None)
    gateway._request = AsyncMock(return_value=response)  # type: ignore[method-assign]
    try:
        assert await gateway.health() is response
    finally:
        await gateway.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        {"status": "unhealthy", "database": "connected"},
        {"status": "healthy", "database": "disconnected"},
        {"status": "healthy"},
        [],
    ],
)
async def test_health_rejects_unhealthy_or_invalid_success_response(response: object) -> None:
    gateway = HindsightGateway("http://hindsight", None)
    gateway._request = AsyncMock(return_value=response)  # type: ignore[method-assign]
    try:
        with pytest.raises(HindsightGatewayError) as exc:
            await gateway.health()
        assert exc.value.code == "hindsight_invalid_response"
        assert exc.value.kind == "invalid-response"
        assert exc.value.context["operation"] == "health"
        assert exc.value.context["method"] == "GET"
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_recall_rejects_deep_upstream_json_before_recursive_scanning() -> None:
    nested: object = "leaf"
    for _ in range(MAX_HINDSIGHT_JSON_DEPTH + 1):
        nested = {"nested": nested}
    response = {"results": [{"id": "m1", "text": "safe", "metadata": nested}]}
    gateway = HindsightGateway("http://hindsight", None)
    gateway._request = AsyncMock(return_value=response)  # type: ignore[method-assign]
    try:
        with pytest.raises(HindsightGatewayError) as exc:
            await gateway.recall("main", {"query": "status"})
        assert exc.value.code == "hindsight_invalid_response"
        assert exc.value.kind == "invalid-response"
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_recall_allows_out_of_range_integer_in_passthrough_fields() -> None:
    response = {"results": [{"id": "m1", "text": "safe", "metadata": {"upstream_counter": 2**63}}]}
    gateway = HindsightGateway("http://hindsight", None)
    gateway._request = AsyncMock(return_value=response)  # type: ignore[method-assign]
    try:
        assert await gateway.recall("main", {"query": "status"}) == response
    finally:
        await gateway.close()


class SlowDripStream(httpx.AsyncByteStream):
    async def __aiter__(self):  # type: ignore[no-untyped-def]
        for chunk in (b'{"results":', b"[]", b"}"):
            await asyncio.sleep(0.02)
            yield chunk


@pytest.mark.asyncio
async def test_request_enforces_absolute_stream_deadline() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=SlowDripStream(), request=request)

    gateway = HindsightGateway("http://hindsight", None, timeout_ms=40)
    await gateway.client.aclose()
    gateway.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), timeout=httpx.Timeout(0.04)
    )
    try:
        with pytest.raises(HindsightGatewayError) as exc:
            await gateway.recall("main", {"query": "status"})
        assert exc.value.code == "hindsight_timeout"
        assert exc.value.kind == "timeout"
    finally:
        await gateway.close()
