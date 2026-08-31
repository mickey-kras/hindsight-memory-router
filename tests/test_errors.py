from __future__ import annotations

import pytest

from memory_router.errors import HttpError, rewrap_rate_limited
from memory_router.hindsight import HindsightGatewayError


def test_hindsight_gateway_error_initializes_typed_http_error() -> None:
    error = HindsightGatewayError("network", operation="recall", method="POST")

    assert str(error) == "Upstream memory service is unavailable"
    assert error.args == ("Upstream memory service is unavailable",)
    assert error.status == 502
    assert error.code == "hindsight_unavailable"
    assert error.headers == {}
    assert error.body() == {
        "error": "hindsight_unavailable",
        "message": "Upstream memory service is unavailable",
    }


def test_hindsight_timeout_preserves_504_mapping() -> None:
    error = HindsightGatewayError("timeout", operation="recall", method="POST", timeout_ms=10_000)

    assert error.status == 504
    assert error.code == "hindsight_timeout"
    assert error.details() == {
        "error_kind": "timeout",
        "status": 504,
        "operation": "recall",
        "method": "POST",
        "timeout_ms": 10_000,
    }


def test_rewrap_rate_limited_replaces_only_429() -> None:
    with pytest.raises(HttpError) as replaced:
        rewrap_rate_limited(
            HttpError(429, "raw", "raw"), code="auth_rate_limited", message="too many"
        )
    assert replaced.value.code == "auth_rate_limited"
    assert replaced.value.status == 429

    original = HttpError(503, "limiter_down", "limiter unavailable")
    with pytest.raises(HttpError) as reraised:
        rewrap_rate_limited(original, code="auth_rate_limited", message="too many")
    assert reraised.value is original
