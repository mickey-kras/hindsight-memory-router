from __future__ import annotations

from collections.abc import AsyncIterator
from unittest.mock import Mock

import httpx
import pytest

from memory_router.errors import HttpError
from memory_router.hindsight import HindsightGateway, HindsightGatewayError
from memory_router.human_auth_config import HumanAuthConfig
from memory_router.human_oidc import HumanOidc
from memory_router.key_wrap import SidecarWrapProvider, WrapSidecarError


class UnreadBody(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        pytest.fail("a rejected encoded response must not be consumed")
        yield b""  # pragma: no cover


@pytest.mark.parametrize("consumer", ["hindsight", "wrap", "oidc"])
@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "GZip", "identity, gzip"])
async def test_encoded_response_rejected_before_decoding(
    consumer: str, encoding: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoder = Mock(side_effect=AssertionError("response decoder must not be constructed"))
    monkeypatch.setattr(httpx.Response, "_get_content_decoder", decoder)

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, headers={"content-encoding": encoding}, stream=UnreadBody())

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        if consumer == "hindsight":
            gateway = HindsightGateway("https://memory.example", None)
            await gateway.client.aclose()
            gateway.client = client
            with pytest.raises(HindsightGatewayError) as upstream:
                await gateway._request("recall", "POST", "/recall", {})
            assert upstream.value.kind == "invalid-response"
        elif consumer == "wrap":
            provider = SidecarWrapProvider("https://wrap.example", None, 1000, "test", 1, 64)
            await provider.client.aclose()
            provider.client = client
            with pytest.raises(WrapSidecarError) as wrapped:
                await provider.wrap(b"k" * 32)
            assert wrapped.value.kind == "invalid-response"
        else:
            oidc = HumanOidc(
                HumanAuthConfig(
                    router_url="https://router.example",
                    issuer="https://id.example",
                    client_id="test",
                    subjects={"subject": "human-test"},
                ),
                client,
            )
            with pytest.raises(HttpError) as identity:
                await oidc._fetch("https://id.example/token", data={"code": "code"})
            assert identity.value.code == "human_login_failed"
        decoder.assert_not_called()
    finally:
        await client.aclose()
