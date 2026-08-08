from __future__ import annotations

import asyncio
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Protocol, Sequence

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from memory_router.config import is_postgres_url


class SqlSession(Protocol):
    dialect: str
    row_lock_clause: str

    def placeholder(self, index: int) -> str: ...
    async def acquire_capacity_lock(self) -> None: ...
    async def execute_script(self, script: str) -> None: ...
    async def run(self, statement: str, params: Sequence[Any] = ()) -> int: ...
    async def get(self, statement: str, params: Sequence[Any] = ()) -> dict[str, Any] | None: ...
    async def all(self, statement: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]: ...


class Database(Protocol):
    dialect: str
    row_lock_clause: str
    def placeholder(self, index: int) -> str: ...
    async def initialize(self) -> None: ...
    async def close(self) -> None: ...
    async def run(self, statement: str, params: Sequence[Any] = ()) -> int: ...
    async def get(self, statement: str, params: Sequence[Any] = ()) -> dict[str, Any] | None: ...
    async def all(self, statement: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]: ...
    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[SqlSession]: ...


class _SqliteSession:
    dialect = "sqlite"
    row_lock_clause = ""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def placeholder(self, _index: int) -> str:
        return "?"

    async def acquire_capacity_lock(self) -> None:
        return None

    async def execute_script(self, script: str) -> None:
        for statement in (part.strip() for part in script.split(";")):
            if statement:
                await self.run(statement)

    async def run(self, statement: str, params: Sequence[Any] = ()) -> int:
        def op() -> int:
            cursor = self._connection.execute(statement, tuple(params))
            return cursor.rowcount
        return await asyncio.to_thread(op)

    async def get(self, statement: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        def op():
            row = self._connection.execute(statement, tuple(params)).fetchone()
            return dict(row) if row is not None else None
        return await asyncio.to_thread(op)

    async def all(self, statement: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        def op():
            return [dict(row) for row in self._connection.execute(statement, tuple(params)).fetchall()]
        return await asyncio.to_thread(op)


class SqliteDatabase:
    dialect = "sqlite"
    row_lock_clause = ""

    def __init__(self, path: str) -> None:
        self._path = path
        self._connection: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    def placeholder(self, _index: int) -> str:
        return "?"

    async def initialize(self) -> None:
        if self._path != ":memory:":
            path = Path(self._path)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._connection = sqlite3.connect(
            self._path, isolation_level=None, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        await asyncio.to_thread(
            self._connection.executescript,
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;",
        )

    def _session(self) -> _SqliteSession:
        if self._connection is None:
            raise RuntimeError("SQLite database is not initialized")
        return _SqliteSession(self._connection)

    async def close(self) -> None:
        if self._connection is not None:
            async with self._lock:
                await asyncio.to_thread(self._connection.close)
                self._connection = None

    async def run(self, statement: str, params: Sequence[Any] = ()) -> int:
        async with self._lock:
            return await self._session().run(statement, params)

    async def get(self, statement: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        async with self._lock:
            return await self._session().get(statement, params)

    async def all(self, statement: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        async with self._lock:
            return await self._session().all(statement, params)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[SqlSession]:
        async with self._lock:
            session = self._session()
            await session.run("BEGIN IMMEDIATE")
            try:
                yield session
            except BaseException:
                await session.run("ROLLBACK")
                raise
            else:
                await session.run("COMMIT")


class _PostgresSession:
    dialect = "postgres"
    row_lock_clause = " FOR UPDATE"

    def __init__(self, connection: psycopg.AsyncConnection[Any]) -> None:
        self._connection = connection

    def placeholder(self, _index: int) -> str:
        return "%s"

    async def acquire_capacity_lock(self) -> None:
        await self.run(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            ("memory-router:quarantine-capacity",),
        )

    async def execute_script(self, script: str) -> None:
        for statement in (part.strip() for part in script.split(";")):
            if statement:
                await self.run(statement)

    async def run(self, statement: str, params: Sequence[Any] = ()) -> int:
        async with self._connection.cursor() as cursor:
            await cursor.execute(statement, tuple(params))
            return cursor.rowcount

    async def get(self, statement: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        async with self._connection.cursor(row_factory=dict_row) as cursor:
            await cursor.execute(statement, tuple(params))
            row = await cursor.fetchone()
            return dict(row) if row is not None else None

    async def all(self, statement: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        async with self._connection.cursor(row_factory=dict_row) as cursor:
            await cursor.execute(statement, tuple(params))
            return [dict(row) for row in await cursor.fetchall()]


class PostgresDatabase:
    dialect = "postgres"
    row_lock_clause = " FOR UPDATE"

    def __init__(self, url: str) -> None:
        self._pool = AsyncConnectionPool(url, min_size=1, max_size=5, open=False)

    def placeholder(self, _index: int) -> str:
        return "%s"

    async def initialize(self) -> None:
        await self._pool.open()
        await self._pool.wait()

    async def close(self) -> None:
        await self._pool.close()

    async def run(self, statement: str, params: Sequence[Any] = ()) -> int:
        async with self._pool.connection() as connection:
            return await _PostgresSession(connection).run(statement, params)

    async def get(self, statement: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        async with self._pool.connection() as connection:
            return await _PostgresSession(connection).get(statement, params)

    async def all(self, statement: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        async with self._pool.connection() as connection:
            return await _PostgresSession(connection).all(statement, params)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[SqlSession]:
        async with self._pool.connection() as connection:
            async with connection.transaction():
                yield _PostgresSession(connection)


def sqlite_path(connection_string: str) -> str:
    value = connection_string[len("sqlite:") :]
    if not value:
        raise ValueError("SQLite database path is required")
    if value == ":memory:":
        return value
    if value.startswith("///"):
        return f"/{value[3:]}"
    if value.startswith("/"):
        return value
    return str(Path(value).resolve())


def create_database(connection_string: str) -> Database:
    if is_postgres_url(connection_string):
        return PostgresDatabase(connection_string)
    if connection_string.startswith("sqlite:"):
        return SqliteDatabase(sqlite_path(connection_string))
    raise ValueError(
        "QUARANTINE_DATABASE_URL must use sqlite:, postgres://, or postgresql://"
    )


def validate_sqlite_storage(connection_string: str) -> None:
    if not connection_string.startswith("sqlite:"):
        return
    path = sqlite_path(connection_string)
    if path == ":memory:":
        return
    target = Path(path)
    directory = target.parent
    if not os.access(directory, os.W_OK):
        raise ValueError(f"quarantine storage at {path} is not writable: directory is not writable")
    if target.exists() and not os.access(target, os.W_OK):
        raise ValueError(f"quarantine storage at {path} is not writable: file is not writable")
