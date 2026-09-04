from __future__ import annotations

from types import SimpleNamespace

import pytest

from memory_router.errors import HttpError
from memory_router.rate_limit import (
    PostgresConcurrencyLimiter,
    PostgresRateLimiter,
    _PostgresSession,
)


class TxContext:
    def __init__(self, tx: object) -> None:
        self.tx = tx

    async def __aenter__(self) -> object:
        return self.tx

    async def __aexit__(self, *args: object) -> None:
        return None


class FakeDatabase:
    def __init__(self, tx: object) -> None:
        self.tx = tx

    def transaction(self) -> TxContext:
        return TxContext(self.tx)


class FakePostgresTx:
    def __init__(self) -> None:
        self.executed: list[tuple[str, object]] = []
        self.state_reads = 0

    async def execute(self, sql: str, params: object = None) -> None:
        self.executed.append((sql, params))

    async def fetchone(self, sql: str, params: object = None) -> dict[str, int] | None:
        if "clock_timestamp" in sql:
            return {"now_ms": 100}
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


async def _result(value: str) -> str:
    return value


@pytest.mark.asyncio
async def test_postgres_concurrency_limiter_acquires_and_releases() -> None:
    tx = FakePostgresTx()
    limiter = PostgresConcurrencyLimiter(FakeDatabase(tx), lease_ms=30_000)
    await limiter.initialize()

    assert await limiter.run("agent:retain", 2, lambda: _result("ok")) == "ok"

    sql = [statement for statement, _ in tx.executed]
    assert any("CREATE TABLE IF NOT EXISTS principal_concurrency_leases" in s for s in sql)
    assert any("pg_advisory_xact_lock" in s for s in sql)
    assert any("INSERT INTO principal_concurrency_leases" in s for s in sql)
    assert any(
        "DELETE FROM principal_concurrency_leases WHERE bucket=? AND lease_id=?" in s for s in sql
    )


@pytest.mark.asyncio
async def test_postgres_concurrency_limiter_rejects_full_bucket() -> None:
    class FullTx(FakePostgresTx):
        async def fetchone(self, sql: str, params: object = None) -> dict[str, int] | None:
            if "clock_timestamp" in sql:
                return {"now_ms": 100}
            if "COUNT(*)" in sql:
                return {"count": 1}
            return None

    with pytest.raises(HttpError):
        await PostgresConcurrencyLimiter(FakeDatabase(FullTx())).run(
            "agent:retain", 1, lambda: _result("never")
        )
