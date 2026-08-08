from __future__ import annotations

import httpx
import pytest

from memory_router.config import HindsightLimitConfig
from memory_router.errors import HttpError
from memory_router.hindsight import HindsightGateway, HindsightGatewayError, gateway_error_kind
from memory_router.rate_limits import HindsightLimits, InMemorySlidingWindowRateLimiter
from memory_router.validation import parse_recall_body, parse_retain_body


@pytest.mark.asyncio
async def test_hindsight_gateway_success_and_headers():
    seen = []

    async def handler(request: httpx.Request):
        seen.append(request)
        if request.url.path.endswith("/recall"):
            return httpx.Response(200, json={"results": [{"id": "m1", "text": "hello", "extra": 1}], "future": True})
        if request.method == "PATCH":
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/health":
            return httpx.Response(200, json={"healthy": True})
        return httpx.Response(200, json={"ok": True})

    gateway = HindsightGateway(
        "http://hindsight:8888/",
        "secret",
        1000,
        transport=httpx.MockTransport(handler),
    )
    assert await gateway.health() == {"healthy": True}
    assert await gateway.retain("main", {"items": []}) == {"ok": True}
    recalled = await gateway.recall("main", {"query": "x"})
    assert recalled.results[0].model_dump()["extra"] == 1
    await gateway.invalidate_memory("main", "m/1", "bad")
    assert seen[0].headers["authorization"] == "Bearer secret"
    assert "%2F" in str(seen[-1].url)
    await gateway.close()


@pytest.mark.asyncio
async def test_hindsight_gateway_error_mapping_and_body_validation():
    cases = [
        (httpx.Response(503, text="secret upstream body"), "hindsight_http_error", 502),
        (httpx.Response(200, text="not-json"), "hindsight_invalid_response", 502),
    ]
    for response, code, status in cases:
        gateway = HindsightGateway(
            "http://h",
            timeout_ms=1000,
            transport=httpx.MockTransport(lambda request, r=response: r),
        )
        with pytest.raises(HindsightGatewayError) as exc:
            await gateway.retain("main", {"items": []})
        assert exc.value.code == code and exc.value.status == status
        assert "secret upstream body" not in exc.value.message
        await gateway.close()

    gateway = HindsightGateway(
        "http://h",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"results": [{"id": 1, "text": "x"}]})),
    )
    with pytest.raises(HindsightGatewayError) as invalid:
        await gateway.recall("main", {"query": "x"})
    assert invalid.value.kind == "invalid-response"
    await gateway.close()


@pytest.mark.asyncio
async def test_hindsight_network_and_stream_timeout_are_stable():
    async def network(_request):
        raise httpx.ConnectError("down")

    gateway = HindsightGateway("http://h", transport=httpx.MockTransport(network))
    with pytest.raises(HindsightGatewayError) as unavailable:
        await gateway.retain("main", {"items": []})
    assert unavailable.value.code == "hindsight_unavailable"
    assert gateway_error_kind(unavailable.value) == "network"
    assert gateway_error_kind(RuntimeError()) == "unknown"
    await gateway.close()

    class TimeoutStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            raise httpx.ReadTimeout("late timeout")
            yield b""  # pragma: no cover

    gateway = HindsightGateway(
        "http://h",
        timeout_ms=123,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=TimeoutStream())),
    )
    with pytest.raises(HindsightGatewayError) as timeout:
        await gateway.retain("main", {"items": []})
    assert timeout.value.code == "hindsight_timeout" and timeout.value.status == 504
    assert timeout.value.details()["timeout_ms"] == 123
    await gateway.close()


def test_hindsight_limits_bounds_and_separate_budgets():
    config = HindsightLimitConfig(
        retain_writer_max=1,
        retain_global_max=2,
        recall_writer_max=1,
        recall_global_max=2,
        rate_limit_window_ms=1000,
        max_retain_items=1,
        max_retain_content_bytes=8,
        max_recall_query_bytes=4,
        max_recall_max_tokens=3,
    )
    limiter = InMemorySlidingWindowRateLimiter()
    limits = HindsightLimits(config, limiter)
    limits.assert_retain_bounds(parse_retain_body({"items": [{"content": "abc"}]}))
    with pytest.raises(HttpError) as items:
        limits.assert_retain_bounds(parse_retain_body({"items": [{"content": "a"}, {"content": "b"}]}))
    assert items.value.code == "retain_item_limit_exceeded"
    with pytest.raises(HttpError) as content:
        limits.assert_retain_bounds(parse_retain_body({"items": [{"content": "123456789"}]}))
    assert content.value.code == "retain_content_too_large"
    with pytest.raises(HttpError) as query:
        limits.assert_recall_bounds(parse_recall_body({"query": "12345"}))
    assert query.value.code == "recall_query_too_large"
    with pytest.raises(HttpError) as tokens:
        limits.assert_recall_bounds(parse_recall_body({"query": "x", "max_tokens": 4}))
    assert tokens.value.code == "recall_max_tokens_exceeded"


@pytest.mark.asyncio
async def test_hindsight_limits_rate_errors_have_retry_after():
    config = HindsightLimitConfig(retain_writer_max=1, retain_global_max=10, recall_writer_max=1, recall_global_max=10, rate_limit_window_ms=1500)
    limits = HindsightLimits(config, InMemorySlidingWindowRateLimiter())
    await limits.consume_retain("main")
    await limits.consume_recall("main")  # separate budget
    with pytest.raises(HttpError) as exc:
        await limits.consume_retain("main")
    assert exc.value.code == "hindsight_rate_limited"
    assert exc.value.headers["retry-after"] == "2"
