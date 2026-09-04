from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, call

import pytest

from memory_router.errors import HttpError
from memory_router.rate_limit import (
    ConcurrencyLeaseLost,
    ConcurrencyLeaseRefreshFailed,
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
        self.executed.append((sql, params))
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
    assert sql.index(
        "DELETE FROM principal_concurrency_leases WHERE bucket=? AND expires_at_ms<=?"
    ) < next(index for index, value in enumerate(sql) if "COUNT(*)" in value)


@pytest.mark.asyncio
async def test_postgres_concurrency_limiter_rejects_full_bucket() -> None:
    class FullTx(FakePostgresTx):
        async def fetchone(self, sql: str, params: object = None) -> dict[str, int] | None:
            if "clock_timestamp" in sql:
                return {"now_ms": 100}
            if "COUNT(*)" in sql:
                return {"count": 1}
            return None

    operation = AsyncMock(return_value="never")
    with pytest.raises(HttpError) as throttled:
        await PostgresConcurrencyLimiter(FakeDatabase(FullTx())).run("agent:retain", 1, operation)
    assert throttled.value.code == "principal_concurrency_limited"
    assert throttled.value.headers == {"retry-after": "1"}
    operation.assert_not_awaited()


@pytest.mark.asyncio
async def test_postgres_concurrency_refresh_requires_live_owned_lease() -> None:
    class RefreshTx(FakePostgresTx):
        async def fetchone(self, sql: str, params: object = None) -> dict[str, int] | None:
            self.executed.append((sql, params))
            if "clock_timestamp" in sql:
                return {"now_ms": 100}
            if "UPDATE principal_concurrency_leases" in sql:
                return {"lease_id": 1}
            return None

    tx = RefreshTx()
    limiter = PostgresConcurrencyLimiter(FakeDatabase(tx))
    await limiter._refresh("agent:retain", "lease-1")

    assert any(
        "expires_at_ms>? RETURNING lease_id" in sql
        and params == (30_100, "agent:retain", "lease-1", 100)
        for sql, params in tx.executed
    )


@pytest.mark.asyncio
async def test_postgres_concurrency_refresh_rejects_lost_lease() -> None:
    class LostTx(FakePostgresTx):
        async def fetchone(self, sql: str, params: object = None) -> dict[str, int] | None:
            if "clock_timestamp" in sql:
                return {"now_ms": 100}
            return None

    with pytest.raises(ConcurrencyLeaseLost):
        await PostgresConcurrencyLimiter(FakeDatabase(LostTx()))._refresh("agent:retain", "lease-1")


@pytest.mark.asyncio
async def test_postgres_concurrency_heartbeat_retries_transient_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleep = AsyncMock()
    limiter = PostgresConcurrencyLimiter(SimpleNamespace(), sleep=sleep)
    refresh = AsyncMock(side_effect=[OSError("temporary"), None, ConcurrencyLeaseLost("lost")])
    monkeypatch.setattr(limiter, "_refresh", refresh)
    with pytest.raises(ConcurrencyLeaseLost):
        await limiter._heartbeat("agent:retain", "lease-1")

    assert refresh.await_count == 3
    assert sleep.await_count == 3
    assert sleep.await_args_list == [call(10.0), call(1.0), call(10.0)]


@pytest.mark.asyncio
async def test_postgres_concurrency_heartbeat_fails_before_expiry_margin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    times = iter((0.0, 21.0))
    limiter = PostgresConcurrencyLimiter(
        SimpleNamespace(), clock=lambda: next(times), sleep=AsyncMock()
    )
    refresh = AsyncMock(side_effect=OSError("database down"))
    monkeypatch.setattr(limiter, "_refresh", refresh)

    with pytest.raises(ConcurrencyLeaseRefreshFailed):
        await limiter._heartbeat("agent:retain", "lease-1")


@pytest.mark.asyncio
async def test_postgres_concurrency_release_failure_does_not_mask_result(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    limiter = PostgresConcurrencyLimiter(FakeDatabase(FakePostgresTx()))
    release = AsyncMock(side_effect=OSError("database down"))
    monkeypatch.setattr(limiter, "_release", release)

    assert await limiter.run("agent:retain", 2, lambda: _result("ok")) == "ok"
    release.assert_awaited_once()
    record = next(
        record for record in caplog.records if record.msg == "principal_concurrency_release_failed"
    )
    assert record.operation == "release-concurrency-lease"
    assert record.error_kind == "storage"
    assert record.outcome == "degraded"
    assert record.error_fingerprint
    assert not any(record.msg == "logging_contract_violation" for record in caplog.records)


def test_postgres_concurrency_rejects_unsafe_lease_duration() -> None:
    with pytest.raises(ValueError, match="at least 3000"):
        PostgresConcurrencyLimiter(SimpleNamespace(), lease_ms=0)
