from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiosqlite
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .rate_limit import (
    InMemoryRateLimiter,
    PostgresConcurrencyLimiter,
    PostgresRateLimiter,
    RateLimiter,
)

CAPACITY_LOCK_ID = 72_499_123
SQLITE_PREFIX = "sqlite:"
SQLITE_MEMORY_PATH = ":memory:"

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS quarantine_items (
 quarantine_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 kind TEXT NOT NULL, reason TEXT NOT NULL, writer_id TEXT, source TEXT,
 source_bank TEXT, source_memory_id TEXT, source_content_sha256 TEXT, dedupe_key TEXT,
 sha256 TEXT NOT NULL, encrypted_envelope TEXT, encrypted_bytes INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL, postpone_count INTEGER NOT NULL DEFAULT 0,
 requarantine_count INTEGER NOT NULL DEFAULT 0, expires_at TEXT)""",
    "CREATE INDEX IF NOT EXISTS idx_quarantine_items_review ON quarantine_items(status, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_quarantine_items_reason ON quarantine_items(reason, status, created_at)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_items_source_memory ON quarantine_items(source_bank, source_memory_id) WHERE source_bank IS NOT NULL AND source_memory_id IS NOT NULL",
    """CREATE TABLE IF NOT EXISTS quarantine_events (
 event_id TEXT PRIMARY KEY, quarantine_id TEXT NOT NULL, occurred_at TEXT NOT NULL,
 event_type TEXT NOT NULL, details TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS idx_quarantine_events_item ON quarantine_events(quarantine_id, occurred_at)",
    "CREATE INDEX IF NOT EXISTS idx_quarantine_events_type ON quarantine_events(event_type, occurred_at)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_items_dedupe_key ON quarantine_items(dedupe_key) WHERE dedupe_key IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_quarantine_items_expires_at ON quarantine_items(expires_at) WHERE expires_at IS NOT NULL",
]


def is_postgres(url: str) -> bool:
    return url.startswith(("postgres://", "postgresql://"))


def sqlite_path(url: str) -> str:
    value = url[len(SQLITE_PREFIX) :]
    if not value:
        raise RuntimeError("SQLite database path is required")
    if value == SQLITE_MEMORY_PATH:
        return value
    if value.startswith("///"):
        return "/" + value[3:]
    if value.startswith("/"):
        return value
    return str(Path(value).resolve())


class Tx:
    dialect: str

    def select_for_update(self, sql: str) -> str:
        raise NotImplementedError

    async def column_exists(self, table: str, column: str) -> bool:
        raise NotImplementedError

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        raise NotImplementedError

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        raise NotImplementedError

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        raise NotImplementedError


class Database:
    dialect: str

    async def initialize(self) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError

    def transaction(self, *, capacity_lock: bool = False) -> AbstractAsyncContextManager[Tx]:
        raise NotImplementedError

    async def ping(self) -> None:
        async with self.transaction() as tx:
            await tx.fetchone("SELECT 1 AS ready")


class SqliteTx(Tx):
    dialect = "sqlite"

    def select_for_update(self, sql: str) -> str:
        return sql

    async def column_exists(self, table: str, column: str) -> bool:
        return bool(
            await self.fetchone(
                "SELECT 1 present FROM pragma_table_info(?) WHERE name=?", (table, column)
            )
        )

    def __init__(self, connection: aiosqlite.Connection) -> None:
        self.connection = connection

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        await self.connection.execute(sql, tuple(params))

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        cursor = await self.connection.execute(sql, tuple(params))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        cursor = await self.connection.execute(sql, tuple(params))
        return [dict(row) for row in await cursor.fetchall()]


class SqliteDatabase(Database):
    dialect = "sqlite"

    def __init__(self, path: str) -> None:
        self.path = path
        self.connection: aiosqlite.Connection | None = None
        self.lock = asyncio.Lock()

    async def initialize(self) -> None:
        if self.path != SQLITE_MEMORY_PATH:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = await aiosqlite.connect(self.path)
        if self.path != SQLITE_MEMORY_PATH:
            os.chmod(self.path, 0o600)
        self.connection.row_factory = aiosqlite.Row
        await self.connection.execute("PRAGMA journal_mode = WAL")
        await self.connection.execute("PRAGMA foreign_keys = ON")
        await self.connection.commit()

    async def close(self) -> None:
        if self.connection:
            await self.connection.close()

    @asynccontextmanager
    async def transaction(self, *, capacity_lock: bool = False) -> AsyncIterator[Tx]:
        del capacity_lock
        if not self.connection:
            raise RuntimeError("database not initialized")
        async with self.lock:
            await self.connection.execute("BEGIN IMMEDIATE")
            tx: Tx = SqliteTx(self.connection)
            try:
                yield tx
            except Exception:
                await self.connection.rollback()
                raise
            else:
                await self.connection.commit()


def _escaped_quote(statement: str, index: int, quote: str) -> bool:
    return index + 1 < len(statement) and statement[index + 1] == quote


class PostgresTx(Tx):
    dialect = "postgres"

    def select_for_update(self, sql: str) -> str:
        return sql + " FOR UPDATE"

    async def column_exists(self, table: str, column: str) -> bool:
        return bool(
            await self.fetchone(
                "SELECT 1 present FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=? AND column_name=?",
                (table, column),
            )
        )

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    @staticmethod
    def sql(statement: str) -> str:
        output: list[str] = []
        index = 0
        active_quote: str | None = None
        while index < len(statement):
            char = statement[index]
            if active_quote is not None:
                output.append(char)
                if char == active_quote and _escaped_quote(statement, index, active_quote):
                    output.append(active_quote)
                    index += 2
                    continue
                if char == active_quote:
                    active_quote = None
            elif char in {"'", '"'}:
                output.append(char)
                active_quote = char
            elif char == "?":
                output.append("%s")
            else:
                output.append(char)
            index += 1
        if active_quote is not None:
            raise ValueError("unterminated SQL quoted literal")
        return "".join(output)

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        await self.connection.execute(self.sql(sql), tuple(params))

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        cursor = await self.connection.execute(self.sql(sql), tuple(params))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        cursor = await self.connection.execute(self.sql(sql), tuple(params))
        return [dict(row) for row in await cursor.fetchall()]


class PostgresDatabase(Database):
    dialect = "postgres"

    def __init__(self, url: str, *, max_size: int = 5) -> None:
        self.pool = AsyncConnectionPool(
            url, min_size=1, max_size=max_size, kwargs={"row_factory": dict_row}, open=False
        )

    async def initialize(self) -> None:
        await self.pool.open()
        await self.pool.wait()

    async def close(self) -> None:
        await self.pool.close()

    @asynccontextmanager
    async def transaction(self, *, capacity_lock: bool = False) -> AsyncIterator[Tx]:
        async with self.pool.connection() as connection:
            async with connection.transaction():
                tx: Tx = PostgresTx(connection)
                if capacity_lock:
                    await tx.execute(f"SELECT pg_advisory_xact_lock({CAPACITY_LOCK_ID})")
                yield tx


async def create_database(url: str) -> Database:
    if is_postgres(url):
        db: Database = PostgresDatabase(url)
    elif url.startswith(SQLITE_PREFIX):
        db = SqliteDatabase(sqlite_path(url))
    else:
        raise RuntimeError(
            "QUARANTINE_DATABASE_URL must use sqlite:, postgres://, or postgresql://"
        )
    await db.initialize()
    await initialize_schema(db)
    return db


@dataclass(frozen=True, slots=True)
class Backend:
    database: Database
    rate_limiter: RateLimiter
    concurrency_limiter: PostgresConcurrencyLimiter | None = None
    rate_limit_database: PostgresDatabase | None = None

    def create_limiter(self) -> RateLimiter:
        return self.rate_limiter if self.rate_limit_database is not None else InMemoryRateLimiter()


async def create_backend(url: str) -> Backend:
    database = await create_database(url)
    if database.dialect != "postgres":
        return Backend(database, InMemoryRateLimiter())
    rate_database = PostgresDatabase(url, max_size=5)
    try:
        await rate_database.initialize()
        limiter = PostgresRateLimiter(rate_database)
        await limiter.initialize()
        concurrency = PostgresConcurrencyLimiter(rate_database)
        await concurrency.initialize()
        return Backend(database, limiter, concurrency, rate_database)
    except BaseException:
        await rate_database.close()
        await database.close()
        raise


async def initialize_schema(db: Database) -> None:
    async with db.transaction(capacity_lock=True) as tx:
        await tx.execute(SCHEMA[0])
        for name, definition in (
            ("dedupe_key", "dedupe_key TEXT"),
            ("requarantine_count", "requarantine_count INTEGER NOT NULL DEFAULT 0"),
            ("expires_at", "expires_at TEXT"),
        ):
            if not await tx.column_exists("quarantine_items", name):
                await tx.execute(f"ALTER TABLE quarantine_items ADD COLUMN {definition}")
        for statement in SCHEMA[1:]:
            await tx.execute(statement)


async def validate_storage(db: Database, url: str) -> None:
    try:
        await db.ping()
    except Exception as exc:
        raise RuntimeError(f"quarantine storage is unreachable: {exc}") from exc
    if not url.startswith(SQLITE_PREFIX):
        return
    path = sqlite_path(url)
    if path == SQLITE_MEMORY_PATH:
        return
    if not os.access(Path(path).parent, os.W_OK) or (
        Path(path).exists() and not os.access(path, os.W_OK)
    ):
        raise RuntimeError(f"quarantine storage at {path} is not writable")
