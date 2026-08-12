from __future__ import annotations

import httpx
import pytest

from memory_router.hindsight import HindsightGateway, HindsightGatewayError


@pytest.mark.asyncio
async def test_openclaw_facade_preserves_upstream_http_status_without_body() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "sensitive provider detail"}, request=request)

    gateway = HindsightGateway("http://hindsight.test", None)
    await gateway.client.aclose()
    gateway.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(HindsightGatewayError) as error:
            await gateway.openclaw_request(
                "openclaw_mental_models", "GET", "/v1/default/banks/main/mental-models/missing"
            )
        assert error.value.status == 404
        assert error.value.body() == {
            "error": "hindsight_http_error",
            "message": "Upstream memory service request failed",
        }
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_core_gateway_keeps_existing_upstream_error_normalization() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "not found"}, request=request)

    gateway = HindsightGateway("http://hindsight.test", None)
    await gateway.client.aclose()
    gateway.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(HindsightGatewayError) as error:
            await gateway.retain("main", {"items": [{"content": "safe"}]})
        assert error.value.status == 502
    finally:
        await gateway.close()
