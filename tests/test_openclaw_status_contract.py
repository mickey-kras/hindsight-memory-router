from __future__ import annotations

import httpx
import pytest

from memory_router.hindsight import HindsightGateway, HindsightGatewayError


@pytest.mark.parametrize("status", [400, 404, 409, 422, 429])
@pytest.mark.asyncio
async def test_openclaw_facade_preserves_sanitized_upstream_client_status(status: int) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"detail": "sensitive provider detail"}, request=request)

    gateway = HindsightGateway("http://hindsight.test", None)
    await gateway.client.aclose()
    gateway.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(HindsightGatewayError) as error:
            await gateway.openclaw_request(
                "openclaw_mental_models", "GET", "/v1/default/banks/main/mental-models/missing"
            )
        assert error.value.status == status
        assert error.value.body() == {
            "error": "hindsight_http_error",
            "message": "Upstream memory service request failed",
        }
    finally:
        await gateway.close()


@pytest.mark.parametrize("status", [301, 302, 401, 403, 500, 503])
@pytest.mark.asyncio
async def test_openclaw_facade_normalizes_redirect_auth_and_server_errors(status: int) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, request=request)

    gateway = HindsightGateway("http://hindsight.test", None)
    await gateway.client.aclose()
    gateway.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(HindsightGatewayError) as error:
            await gateway.openclaw_request("openclaw_tags", "GET", "/v1/default/banks/main/tags")
        assert error.value.status == 502
        assert error.value.upstream_status == status
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
