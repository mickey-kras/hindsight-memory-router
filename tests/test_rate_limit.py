from __future__ import annotations

from types import SimpleNamespace

import pytest

from memory_router.rate_limit import PostgresRateLimiter, _PostgresSession


class FakePostgresTx:
    def __init__(self) -> None:
        self.executed: list[tuple[str, object]] = []
        self.state_reads = 0

    async def execute(self, sql: str, params: object = None) -> None:
        self.executed.append((sql, params))

    async def fetchone(self, sql: str, params: object = None) -> dict[str, int] | None:
        if "SELECT max_window_ms" in sql:
            self.state_reads += 1
            return {"max_window_ms": 60_000}
        if "COUNT(*)" in sql:
            return {"count": 0}
        return None


@pytest.mark.asyncio
async def test_postgres_max_window_cache_updates_only_after_commit() -> None:
    tx = FakePostgresTx()
    limiter = PostgresRateLimiter(SimpleNamespace())
    cache = limiter.max_window_cache

    first = _PostgresSession(tx, max_window_cache=cache)
    await first.consume_many([("first", 10, 10_000)], at_ms=100_000)
    assert tx.state_reads == 1
    assert cache[0] == 0
    assert first.observed_max_window == 60_000
    assert not any("INSERT INTO quarantine_rate_limit_state" in sql for sql, _ in tx.executed)

    limiter._commit_session(first)
    assert cache[0] == 60_000

    second = _PostgresSession(tx, max_window_cache=cache)
    await second.consume_many([("second", 10, 10_000)], at_ms=100_001)
    assert tx.state_reads == 1

    rolled_back = _PostgresSession(tx, max_window_cache=cache)
    await rolled_back.consume_many([("larger", 10, 120_000)], at_ms=100_002)
    assert tx.state_reads == 2
    assert cache[0] == 60_000
    assert rolled_back.observed_max_window == 120_000

    retried = _PostgresSession(tx, max_window_cache=cache)
    await retried.consume_many([("larger-retry", 10, 120_000)], at_ms=100_003)
    assert tx.state_reads == 3
    assert cache[0] == 60_000
    state_writes = [
        sql for sql, _ in tx.executed if "INSERT INTO quarantine_rate_limit_state" in sql
    ]
    assert len(state_writes) == 2

    limiter._commit_session(retried)
    assert cache[0] == 120_000
