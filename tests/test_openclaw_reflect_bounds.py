from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from memory_router.errors import HttpError
from memory_router.limits import HindsightLimitConfig, HindsightLimits
from memory_router.openclaw import OpenClawFacade


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"query": "x" * 17, "max_tokens": 1}, "recall_query_too_large"),
        ({"query": "safe query", "max_tokens": 33}, "recall_max_tokens_exceeded"),
    ],
)
@pytest.mark.asyncio
async def test_reflect_enforces_recall_bounds_before_quota_or_hindsight(
    body: dict[str, object], code: str
) -> None:
    limiter = SimpleNamespace(consume_many=AsyncMock())
    limits = HindsightLimits(
        HindsightLimitConfig(max_recall_query_bytes=16, max_recall_max_tokens=32), limiter
    )
    hindsight = SimpleNamespace(openclaw_request=AsyncMock())
    policy = SimpleNamespace(
        registry=SimpleNamespace(
            writers={
                "openclaw": SimpleNamespace(
                    write_bank="physical-main", read_banks=["physical-main"]
                )
            }
        ),
        hindsight=hindsight,
        limits=limits,
        _quarantine=AsyncMock(),
    )

    with pytest.raises(HttpError) as blocked:
        await OpenClawFacade(policy).forward(
            writer_id="openclaw",
            method="POST",
            resource="reflect",
            body=body,
            read_operation=True,
        )

    assert blocked.value.status == 413
    assert blocked.value.code == code
    hindsight.openclaw_request.assert_not_awaited()
    limiter.consume_many.assert_not_awaited()
