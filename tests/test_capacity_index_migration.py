from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from memory_router import db as db_module


class Cursor:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self.row = row

    async def fetchone(self) -> dict[str, Any] | None:
        return self.row


class MigrationServer:
    def __init__(self) -> None:
        self.schema_lock = asyncio.Lock()
        self.capacity_lock = asyncio.Lock()
        self.indices: dict[str, bool] = {}
        self.connections: list[MigrationConnection] = []
        self.build_started = asyncio.Event()
        self.release_build = asyncio.Event()
        self.release_build.set()
        self.failure: BaseException | None = None
        self.failed_lock_attempt = asyncio.Event()
        self.snapshot_wait_started = asyncio.Event()

    def database(self) -> db_module.PostgresDatabase:
        db = db_module.PostgresDatabase("postgresql://migration-test")
        server = self

        class SchemaTx(db_module.Tx):
            dialect = "postgres"

            async def column_exists(self, table: str, column: str) -> bool:
                return True

            async def fetchone(self, sql: str, params: Any = ()) -> dict[str, Any]:
                assert "pg_indexes" in sql
                return {"present": 1}

            async def execute(self, sql: str, params: Any = ()) -> None:
                assert "idx_quarantine_capacity_" not in sql
                # Existing legacy indexes must not request another table lock.
                assert "CREATE INDEX" not in sql and "CREATE UNIQUE INDEX" not in sql

        @asynccontextmanager
        async def transaction(*, capacity_lock: bool = False):
            assert capacity_lock
            async with server.capacity_lock:
                yield SchemaTx()

        db.transaction = transaction  # type: ignore[method-assign]
        return db

    async def connect(self, url: str, **kwargs: Any) -> MigrationConnection:
        assert kwargs["autocommit"] is True
        connection = MigrationConnection(self)
        self.connections.append(connection)
        return connection


class MigrationConnection:
    def __init__(self, server: MigrationServer) -> None:
        self.server = server
        self.owns_lock = False
        self.closed = False
        self.calls: list[str] = []
        self.close_started = asyncio.Event()
        self.release_close = asyncio.Event()
        self.release_close.set()
        self.statement_active = False
        self.statement_finished = asyncio.Event()
        self.statement_finished.set()

    async def execute(self, query: Any, params: Any = ()) -> Cursor:
        self.statement_active = True
        self.statement_finished.clear()
        try:
            return await self._execute(query, params)
        finally:
            # An autocommit statement releases its snapshot when it finishes.
            self.statement_active = False
            self.statement_finished.set()

    async def _execute(self, query: Any, params: Any = ()) -> Cursor:
        statement = query if isinstance(query, str) else query.as_string()
        self.calls.append(statement)
        if "pg_try_advisory_lock" in statement or "pg_advisory_lock" in statement:
            assert str(db_module.SCHEMA_LOCK_ID) in statement
            assert db_module.SCHEMA_LOCK_ID != db_module.CAPACITY_LOCK_ID
            if "pg_try_advisory_lock" in statement and self.server.schema_lock.locked():
                self.server.failed_lock_attempt.set()
                return Cursor({"acquired": False})
            await self.server.schema_lock.acquire()
            self.owns_lock = True
            return Cursor({"acquired": True})
        elif "FROM pg_index" in statement:
            name = params[0]
            if name in self.server.indices:
                return Cursor({"valid": self.server.indices[name], "schema_name": "upgrade schema"})
        elif statement.startswith("DROP INDEX"):
            assert statement.startswith('DROP INDEX CONCURRENTLY "upgrade schema".')
            name = statement.rsplit('"', 2)[1]
            del self.server.indices[name]
        elif statement.startswith("CREATE INDEX"):
            assert statement.startswith("CREATE INDEX CONCURRENTLY ")
            assert not self.server.capacity_lock.locked(), "build blocks capacity admissions"
            name = statement.split(" ON ", 1)[0].rsplit(" ", 1)[1]
            self.server.indices[name] = False
            self.server.build_started.set()
            await self.server.release_build.wait()
            # Partial concurrent builds wait for transactions with old snapshots,
            # including another session's still-running advisory lock statement.
            for peer in self.server.connections:
                if peer is not self and peer.statement_active:
                    self.server.snapshot_wait_started.set()
                    await peer.statement_finished.wait()
            if self.server.failure:
                raise self.server.failure
            self.server.indices[name] = True
        return Cursor(None)

    async def close(self) -> None:
        self.close_started.set()
        await self.release_close.wait()
        self.closed = True
        if self.owns_lock:
            self.server.schema_lock.release()
            self.owns_lock = False


@pytest.mark.asyncio
async def test_replica_migrations_do_not_hold_admission_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = MigrationServer()
    server.release_build.clear()
    monkeypatch.setattr(db_module.AsyncConnection, "connect", server.connect)
    first = asyncio.create_task(db_module.initialize_schema(server.database()))
    await asyncio.wait_for(server.build_started.wait(), 1)
    second = asyncio.create_task(db_module.initialize_schema(server.database()))
    try:
        # The second initializer waits on the session lock before entering capacity Tx.
        while len(server.connections) < 2:
            await asyncio.sleep(0)
        async with asyncio.timeout(1):
            async with server.capacity_lock:
                assert not second.done()
                assert server.connections[0].owns_lock
                assert not server.connections[1].owns_lock
        server.release_build.set()
        await asyncio.wait_for(asyncio.gather(first, second), 1)
        assert len(server.indices) == 7 and all(server.indices.values())
        assert all(connection.closed for connection in server.connections)
        assert not any("CREATE INDEX" in sql for sql in server.connections[1].calls)
    finally:
        server.release_build.set()
        first.cancel()
        second.cancel()
        await asyncio.gather(first, second, return_exceptions=True)


@pytest.mark.asyncio
async def test_blocking_lock_statement_prevents_partial_index_snapshot_validation() -> None:
    server = MigrationServer()
    owner = await server.connect("postgresql://migration-test", autocommit=True)
    waiter = await server.connect("postgresql://migration-test", autocommit=True)
    await owner.execute(f"SELECT pg_advisory_lock({db_module.SCHEMA_LOCK_ID})")
    server.release_build.clear()
    build = asyncio.create_task(
        owner.execute("CREATE INDEX CONCURRENTLY test ON quarantine_items(status)")
    )
    await server.build_started.wait()
    waiting = asyncio.create_task(
        waiter.execute(f"SELECT pg_advisory_lock({db_module.SCHEMA_LOCK_ID})")
    )
    try:
        while not waiter.statement_active:
            await asyncio.sleep(0)
        server.release_build.set()
        await asyncio.wait_for(server.snapshot_wait_started.wait(), 1)
        assert not build.done() and not waiting.done()
        assert owner.owns_lock and waiter.statement_active
        # Aborting the waiting statement releases the snapshot, as in the hosted
        # deadlock detector's victim selection, and permits the index to finish.
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        await asyncio.wait_for(build, 1)
    finally:
        build.cancel()
        waiting.cancel()
        await asyncio.gather(build, waiting, return_exceptions=True)
        await owner.close()
        await waiter.close()


@pytest.mark.asyncio
async def test_waiting_replica_releases_snapshot_before_partial_index_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = MigrationServer()
    server.release_build.clear()
    monkeypatch.setattr(db_module.AsyncConnection, "connect", server.connect)
    first = asyncio.create_task(db_module.initialize_schema(server.database()))
    await asyncio.wait_for(server.build_started.wait(), 1)
    second = asyncio.create_task(db_module.initialize_schema(server.database()))
    try:
        await asyncio.wait_for(server.failed_lock_attempt.wait(), 1)
        assert not server.connections[1].statement_active
        assert not second.done()
        server.release_build.set()
        await asyncio.wait_for(asyncio.gather(first, second), 1)
        assert all(server.indices.values()) and len(server.indices) == 7
        assert all(connection.closed for connection in server.connections)
    finally:
        server.release_build.set()
        first.cancel()
        second.cancel()
        await asyncio.gather(first, second, return_exceptions=True)


@pytest.mark.asyncio
async def test_invalid_capacity_index_is_repaired_after_failed_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = MigrationServer()
    server.failure = RuntimeError("build failed")
    monkeypatch.setattr(db_module.AsyncConnection, "connect", server.connect)
    with pytest.raises(RuntimeError, match="build failed"):
        await db_module.initialize_schema(server.database())
    assert server.connections[0].closed and not server.schema_lock.locked()
    server.failure = None
    await db_module.initialize_schema(server.database())
    assert any(sql.startswith("DROP INDEX CONCURRENTLY") for sql in server.connections[1].calls)
    assert len(server.indices) == 7 and all(server.indices.values())


@pytest.mark.asyncio
async def test_cancelled_build_drains_close_and_releases_session_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = MigrationServer()
    server.release_build.clear()
    monkeypatch.setattr(db_module.AsyncConnection, "connect", server.connect)
    task = asyncio.create_task(db_module.initialize_schema(server.database()))
    await asyncio.wait_for(server.build_started.wait(), 1)
    connection = server.connections[0]
    connection.release_close.clear()
    task.cancel()
    await asyncio.wait_for(connection.close_started.wait(), 1)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done() and server.schema_lock.locked()
    connection.release_close.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert connection.closed and not server.schema_lock.locked()
    server.release_build.set()
    await db_module.initialize_schema(server.database())
    assert len(server.indices) == 7 and all(server.indices.values())


@pytest.mark.asyncio
async def test_cancelled_waiting_replica_does_not_release_other_session_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = MigrationServer()
    server.release_build.clear()
    monkeypatch.setattr(db_module.AsyncConnection, "connect", server.connect)
    first = asyncio.create_task(db_module.initialize_schema(server.database()))
    await asyncio.wait_for(server.build_started.wait(), 1)
    second = asyncio.create_task(db_module.initialize_schema(server.database()))
    try:
        async with asyncio.timeout(1):
            while len(server.connections) < 2:
                await asyncio.sleep(0)
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
        assert server.connections[1].closed and server.connections[0].owns_lock
        async with asyncio.timeout(1):
            async with server.capacity_lock:
                assert server.schema_lock.locked()
        server.release_build.set()
        await asyncio.wait_for(first, 1)
    finally:
        server.release_build.set()
        first.cancel()
        second.cancel()
        await asyncio.gather(first, second, return_exceptions=True)


@pytest.mark.asyncio
async def test_schema_error_closes_dedicated_session(monkeypatch: pytest.MonkeyPatch) -> None:
    server = MigrationServer()
    monkeypatch.setattr(db_module.AsyncConnection, "connect", server.connect)
    monkeypatch.setattr(
        db_module,
        "_initialize_schema_transaction",
        AsyncMock(side_effect=RuntimeError("schema failed")),
    )
    with pytest.raises(RuntimeError, match="schema failed"):
        await db_module.initialize_schema(server.database())
    assert server.connections[0].closed and not server.schema_lock.locked()


@pytest.mark.asyncio
async def test_sqlite_capacity_indexes_remain_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = db_module.SqliteDatabase(str(tmp_path / "atomic.db"))
    await db.initialize()
    original = db_module.SqliteTx.execute

    async def fail_index(tx: db_module.SqliteTx, statement: str, params: Any = ()) -> None:
        if "idx_quarantine_capacity_bytes" in statement:
            raise RuntimeError("index failed")
        await original(tx, statement, params)

    try:
        monkeypatch.setattr(db_module.SqliteTx, "execute", fail_index)
        with pytest.raises(RuntimeError, match="index failed"):
            await db_module.initialize_schema(db)
        async with db.transaction() as tx:
            assert not await tx.fetchone(
                "SELECT name FROM sqlite_master WHERE name='quarantine_items'"
            )
        monkeypatch.setattr(db_module.SqliteTx, "execute", original)
        await db_module.initialize_schema(db)
        async with db.transaction() as tx:
            assert (
                len(
                    await tx.fetchall(
                        "SELECT name FROM sqlite_master WHERE name LIKE 'idx_quarantine_capacity_%'"
                    )
                )
                == 7
            )
    finally:
        await db.close()
