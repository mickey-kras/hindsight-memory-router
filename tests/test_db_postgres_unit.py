from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from memory_router.errors import HttpError
from memory_router.quarantine.db import (
    SqliteDatabase,
    create_database,
    sqlite_path,
    validate_sqlite_storage,
)
from memory_router.rate_limits import (
    Bucket,
    DistinctIdentity,
    PostgresSlidingWindowRateLimiter,
    Rule,
    _normalize_buckets,
    _normalize_distinct,
)


@pytest.mark.asyncio
async def test_sqlite_database_transactions_paths_and_validation(tmp_path, monkeypatch):
    db = SqliteDatabase(":memory:")
    with pytest.raises(RuntimeError):
        await db.get("select 1")
    await db.initialize()
    assert db.placeholder(1) == "?"
    await db.run("CREATE TABLE t(x INTEGER)")
    async with db.transaction() as tx:
        assert tx.dialect == "sqlite" and tx.row_lock_clause == ""
        await tx.acquire_capacity_lock()
        await tx.execute_script("INSERT INTO t VALUES (1); INSERT INTO t VALUES (2);")
    assert len(await db.all("SELECT * FROM t")) == 2
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await tx.run("INSERT INTO t VALUES (3)")
            raise RuntimeError("rollback")
    assert len(await db.all("SELECT * FROM t")) == 2
    await db.close(); await db.close()

    assert sqlite_path("sqlite::memory:") == ":memory:"
    assert sqlite_path("sqlite:///tmp/x.db") == "/tmp/x.db"
    assert sqlite_path("sqlite:/tmp/x.db") == "/tmp/x.db"
    assert Path(sqlite_path("sqlite:relative.db")).is_absolute()
    with pytest.raises(ValueError): sqlite_path("sqlite:")
    assert create_database("sqlite::memory:").dialect == "sqlite"
    import memory_router.quarantine.db as db_module
    original_pg = db_module.PostgresDatabase
    monkeypatch.setattr(db_module, "PostgresDatabase", lambda _url: type("P", (), {"dialect":"postgres"})())
    assert create_database("postgresql://db/x").dialect == "postgres"
    monkeypatch.setattr(db_module, "PostgresDatabase", original_pg)
    with pytest.raises(ValueError): create_database("mysql://db")
    validate_sqlite_storage("postgresql://db/x")
    validate_sqlite_storage("sqlite::memory:")

    target = tmp_path / "x.db"
    target.touch()
    # Patch os.access so both directory and file failure branches are deterministic.
    monkeypatch.setattr(db_module.os, "access", lambda path, mode: False)
    with pytest.raises(ValueError, match="directory"):
        validate_sqlite_storage(f"sqlite:{target}")
    monkeypatch.setattr(db_module.os, "access", lambda path, mode: Path(path) != target)
    with pytest.raises(ValueError, match="file"):
        validate_sqlite_storage(f"sqlite:{target}")


class FakeTx:
    dialect = "postgres"
    row_lock_clause = " FOR UPDATE"
    def __init__(self, *, event_count=0, identity_count=0, existing=(), now=1000):
        self.event_count=event_count; self.identity_count=identity_count; self.existing=existing; self.now=now
        self.runs=[]; self.script=""
    def placeholder(self, _): return "%s"
    async def acquire_capacity_lock(self): pass
    async def execute_script(self, script): self.script = script
    async def run(self, statement, params=()): self.runs.append((statement,tuple(params))); return 1
    async def get(self, statement, params=()):
        if "clock_timestamp" in statement: return {"now_ms":self.now}
        if "rate_limit_events" in statement: return {"count":self.event_count}
        if "rate_limit_identities" in statement: return {"count":self.identity_count}
        return None
    async def all(self, statement, params=()):
        if "rate_limit_identities" in statement: return [{"identity":x} for x in self.existing]
        return []


class FakeDb:
    def __init__(self, tx): self.tx=tx; self.initialized=False; self.closed=False
    async def initialize(self): self.initialized=True
    async def close(self): self.closed=True
    @asynccontextmanager
    async def transaction(self): yield self.tx


@pytest.mark.asyncio
async def test_postgres_rate_limiter_transaction_logic(monkeypatch):
    import memory_router.rate_limits as module
    tx = FakeTx()
    fake_db = FakeDb(tx)
    monkeypatch.setattr(module, "PostgresDatabase", lambda _url: fake_db)
    limiter = PostgresSlidingWindowRateLimiter("postgresql://db/x")
    await limiter.initialize()
    assert fake_db.initialized and "quarantine_rate_limit_events" in tx.script

    await limiter.consume_many_distinct(
        [Bucket("b", Rule(2,100))],
        [DistinctIdentity("s","i",Rule(2,100))],
        at_ms=1000,
    )
    assert any("INSERT INTO quarantine_rate_limit_events" in sql for sql,_ in tx.runs)
    assert any("INSERT INTO quarantine_rate_limit_identities" in sql for sql,_ in tx.runs)

    # no-op disabled rules
    await limiter.consume_many([Bucket("off", Rule(0,100))], at_ms=1000)

    # Database clock branch.
    await limiter.consume("b2", Rule(2,100), at_ms=None)

    # Shared transaction adapter/identity lock uses the same tx.
    async def operation(session):
        await session.consume("inner", Rule(2,100), 1000)
        await session.consume_many([Bucket("inner2",Rule(2,100))],1000)
        await session.consume_many_distinct([], [DistinctIdentity("s2","i2",Rule(2,100))],1000)
        return "ok"
    assert await limiter.with_identity_lock("key", operation) == "ok"
    await limiter.close(); assert fake_db.closed

    limited = PostgresSlidingWindowRateLimiter("postgresql://db/x")
    limited._db = FakeDb(FakeTx(event_count=1))
    with pytest.raises(HttpError):
        await limited.consume("b", Rule(1,100), 1000)

    distinct_limited = PostgresSlidingWindowRateLimiter("postgresql://db/x")
    distinct_limited._db = FakeDb(FakeTx(identity_count=1, existing=()))
    with pytest.raises(HttpError):
        await distinct_limited.consume_many_distinct([], [DistinctIdentity("s","new",Rule(1,100))],1000)

    # Existing identity does not count as an addition.
    existing = PostgresSlidingWindowRateLimiter("postgresql://db/x")
    existing._db = FakeDb(FakeTx(identity_count=1, existing=("same",)))
    await existing.consume_many_distinct([], [DistinctIdentity("s","same",Rule(1,100))],1000)


def test_rate_limit_normalization():
    assert _normalize_buckets([Bucket("b",Rule(1,1)),Bucket("b",Rule(2,2)),Bucket("off",Rule(0,1))])[0].rule.max == 2
    assert _normalize_distinct([DistinctIdentity("s","i",Rule(1,1)),DistinctIdentity("s","i",Rule(2,2)),DistinctIdentity("s","off",Rule(0,1))])[0].rule.max == 2
