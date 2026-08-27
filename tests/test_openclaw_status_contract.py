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


@pytest.mark.parametrize(("upstream", "expected"), [(202, 201), (204, 200)])
@pytest.mark.asyncio
async def test_openclaw_facade_rejects_unexpected_success_status(
    upstream: int, expected: int
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(upstream, request=request)

    gateway = HindsightGateway("http://hindsight.test", None)
    await gateway.client.aclose()
    gateway.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(HindsightGatewayError) as error:
            await gateway.openclaw_request(
                "openclaw_create", "POST", "/resource", expected_status=expected
            )
        assert error.value.code == "hindsight_invalid_response"
        assert error.value.upstream_status == upstream
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_openclaw_facade_allows_empty_body_only_for_explicit_routes() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request)

    gateway = HindsightGateway("http://hindsight.test", None)
    await gateway.client.aclose()
    gateway.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        assert (
            await gateway.openclaw_request(
                "openclaw_delete",
                "DELETE",
                "/resource",
                allow_empty_response=True,
            )
            is None
        )
        with pytest.raises(HindsightGatewayError, match="invalid response"):
            await gateway.openclaw_request("openclaw_get", "GET", "/resource")
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_bodyless_upstream_request_omits_json_content_type() -> None:
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={}, request=request)

    gateway = HindsightGateway("http://hindsight.test", None)
    await gateway.client.aclose()
    gateway.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        await gateway.openclaw_request("openclaw_get", "GET", "/resource")
    finally:
        await gateway.close()

    assert "content-type" not in seen[0].headers
