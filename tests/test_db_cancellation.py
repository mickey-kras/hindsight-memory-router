from __future__ import annotations

import asyncio
import sqlite3
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import aiosqlite
import pytest

from memory_router.db import SQLITE_MEMORY_PATH, SqliteDatabase


@pytest.fixture
async def database() -> AsyncIterator[SqliteDatabase]:
    database = SqliteDatabase(SQLITE_MEMORY_PATH)
    await database.initialize()
    try:
        async with database.transaction() as tx:
            await tx.execute("CREATE TABLE items (value INTEGER PRIMARY KEY)")
        yield database
    finally:
        await database.close()


@asynccontextmanager
async def paused_statement(
    connection: aiosqlite.Connection, statement: str
) -> AsyncIterator[tuple[asyncio.Event, threading.Event]]:
    started = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()

    def trace(sql: str) -> None:
        if sql == statement:
            loop.call_soon_threadsafe(started.set)
            release.wait(timeout=5)

    await connection.set_trace_callback(trace)
    try:
        yield started, release
    finally:
        release.set()
        await connection.set_trace_callback(None)


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("BEGIN IMMEDIATE", []),
        ("INSERT INTO items VALUES (1)", []),
        ("COMMIT", [{"value": 1}]),
    ],
    ids=["begin", "pending-write", "commit-already-dispatched"],
)
async def test_cancellation_drains_sqlite_worker_before_connection_reuse(
    database: SqliteDatabase, statement: str, expected: list[dict[str, int]]
) -> None:
    connection = database.connection
    assert connection is not None

    async def insert() -> None:
        async with database.transaction() as tx:
            await tx.execute("INSERT INTO items VALUES (1)")

    async with paused_statement(connection, statement) as (started, release):
        transaction = asyncio.create_task(insert())
        await asyncio.wait_for(started.wait(), timeout=2)
        transaction.cancel("request cancelled")
        next_request = asyncio.create_task(database.ping())
        await asyncio.sleep(0)
        assert not transaction.done()
        assert not next_request.done()
        release.set()
        with pytest.raises(asyncio.CancelledError, match="request cancelled"):
            await asyncio.wait_for(transaction, timeout=2)
        await asyncio.wait_for(next_request, timeout=2)

    async with database.transaction() as tx:
        assert await tx.fetchall("SELECT value FROM items") == expected
        await tx.execute("INSERT INTO items VALUES (2)")
    async with database.transaction() as tx:
        assert await tx.fetchone("SELECT value FROM items WHERE value=2") == {"value": 2}


@pytest.mark.parametrize("cancel_body", [False, True], ids=["body-error", "body-cancelled"])
async def test_repeated_cancellation_waits_for_rollback_and_preserves_original_error(
    database: SqliteDatabase, cancel_body: bool
) -> None:
    connection = database.connection
    assert connection is not None
    body_ready = asyncio.Event()
    original_error = RuntimeError("transaction failed")

    async def insert() -> None:
        async with database.transaction() as tx:
            await tx.execute("INSERT INTO items VALUES (1)")
            body_ready.set()
            if cancel_body:
                await asyncio.Event().wait()
            raise original_error

    async with paused_statement(connection, "ROLLBACK") as (started, release):
        transaction = asyncio.create_task(insert())
        await asyncio.wait_for(body_ready.wait(), timeout=2)
        if cancel_body:
            transaction.cancel("original cancellation")
        await asyncio.wait_for(started.wait(), timeout=2)
        next_request = asyncio.create_task(database.ping())
        for _ in range(2):
            transaction.cancel("later cancellation")
            await asyncio.sleep(0)
            assert not transaction.done()
            assert not next_request.done()
        release.set()
        if cancel_body:
            with pytest.raises(asyncio.CancelledError, match="original cancellation"):
                await asyncio.wait_for(transaction, timeout=2)
        else:
            with pytest.raises(RuntimeError) as raised:
                await asyncio.wait_for(transaction, timeout=2)
            assert raised.value is original_error
        await asyncio.wait_for(next_request, timeout=2)

    async with database.transaction() as tx:
        assert await tx.fetchall("SELECT value FROM items") == []


async def test_commit_failure_rolls_back_pending_writes_and_allows_reuse(
    database: SqliteDatabase,
) -> None:
    async with database.transaction() as tx:
        await tx.execute(
            "CREATE TABLE children (parent INTEGER REFERENCES items(value) "
            "DEFERRABLE INITIALLY DEFERRED)"
        )

    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
        async with database.transaction() as tx:
            await tx.execute("INSERT INTO children VALUES (99)")

    await database.ping()
    async with database.transaction() as tx:
        assert await tx.fetchall("SELECT parent FROM children") == []


@pytest.mark.parametrize("cancel_body", [False, True], ids=["body-error", "body-cancelled"])
async def test_rollback_failure_closes_connection_and_preserves_original_error(
    database: SqliteDatabase, cancel_body: bool
) -> None:
    connection = database.connection
    assert connection is not None

    def authorize(
        action: int,
        argument: str | None,
        _second: str | None,
        _db: str | None,
        _trigger: str | None,
    ) -> int:
        if action == sqlite3.SQLITE_TRANSACTION and argument == "ROLLBACK":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    await connection.set_authorizer(authorize)
    original_error = (
        asyncio.CancelledError("request cancelled")
        if cancel_body
        else RuntimeError("transaction failed")
    )
    with pytest.raises(type(original_error)) as raised:
        async with database.transaction() as tx:
            await tx.execute("INSERT INTO items VALUES (1)")
            waiter = asyncio.create_task(database.ping())
            await asyncio.sleep(0)
            raise original_error

    assert raised.value is original_error
    assert isinstance(raised.value.__cause__, sqlite3.DatabaseError)
    with pytest.raises(ValueError, match="no active connection"):
        await connection.execute("SELECT 1")
    with pytest.raises(RuntimeError, match="database not initialized"):
        await waiter


async def test_cancelled_lock_waiter_does_not_rollback_active_transaction(
    database: SqliteDatabase,
) -> None:
    async with database.transaction() as tx:
        await tx.execute("INSERT INTO items VALUES (1)")
        waiter = asyncio.create_task(database.ping())
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter

    async with database.transaction() as tx:
        assert await tx.fetchall("SELECT value FROM items") == [{"value": 1}]
