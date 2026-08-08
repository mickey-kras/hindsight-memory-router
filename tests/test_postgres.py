from __future__ import annotations

import os

import pytest

from memory_router.config import HindsightLimitConfig
from memory_router.errors import HttpError
from memory_router.rate_limits import HindsightLimits, PostgresSlidingWindowRateLimiter


POSTGRES_URL = os.getenv("TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="TEST_POSTGRES_URL is not configured")


@pytest.mark.asyncio
async def test_postgres_hindsight_limits_are_shared_across_instances() -> None:
    assert POSTGRES_URL is not None
    first = PostgresSlidingWindowRateLimiter(POSTGRES_URL)
    second = PostgresSlidingWindowRateLimiter(POSTGRES_URL)
    await first.initialize()
    await second.initialize()
    try:
        async with first._db.transaction() as tx:
            await tx.run("DELETE FROM quarantine_rate_limit_events")
            await tx.run("DELETE FROM quarantine_rate_limit_identities")

        config = HindsightLimitConfig(
            retain_writer_max=1,
            retain_global_max=2,
            recall_writer_max=1,
            recall_global_max=2,
            rate_limit_window_ms=60_000,
        )
        first_limits = HindsightLimits(config, first)
        second_limits = HindsightLimits(config, second)

        await first_limits.consume_retain("writer-a")
        with pytest.raises(HttpError) as writer_limit:
            await second_limits.consume_retain("writer-a")
        assert writer_limit.value.status == 429
        assert writer_limit.value.code == "hindsight_rate_limited"

        await second_limits.consume_retain("writer-b")
        with pytest.raises(HttpError) as global_limit:
            await first_limits.consume_retain("writer-c")
        assert global_limit.value.status == 429
        assert global_limit.value.code == "hindsight_rate_limited"

        # Recall uses independent buckets from retain, shared across replicas.
        await second_limits.consume_recall("writer-a")
        with pytest.raises(HttpError) as recall_limit:
            await first_limits.consume_recall("writer-a")
        assert recall_limit.value.code == "hindsight_rate_limited"
    finally:
        await first.close()
        await second.close()
