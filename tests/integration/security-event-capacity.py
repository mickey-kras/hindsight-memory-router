from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import AsyncExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.db import PostgresDatabase, create_database, is_postgres
from memory_router.errors import HttpError
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore
from memory_router.rate_limit import InMemoryRateLimiter
from memory_router.repository import QuarantineRepository

AT = "2026-09-22T00:00:00.000Z"


def event(index: int, writer: str = "alice", bank: str = "alpha") -> dict[str, Any]:
    return {
        "timestamp": AT,
        "kind": "security_event",
        "reason": "denied_endpoint",
        "writerId": writer,
        "bankId": bank,
        "dedupeKey": str(index),
        "payload": {"junk": index},
    }


async def expect_capacity(store: QuarantineStore, value: dict[str, Any], code: str) -> None:
    try:
        await store.put(value)
    except HttpError as error:
        assert error.status == 507 and error.code == code, error
    else:
        raise AssertionError("over-capacity audit identity was admitted")


async def verify_capacity(url: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    pem = key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    async with AsyncExitStack() as resources:
        databases = []
        for _ in range(2):
            database = await create_database(url)
            resources.push_async_callback(database.close)
            databases.append(database)
        repositories = [QuarantineRepository(database) for database in databases]
        scoped = [
            QuarantineStore(
                pem,
                repository,
                QuarantineLimits(
                    max_pending_items=4,
                    max_pending_items_per_writer=1,
                    max_pending_items_per_bank=1,
                    rate_limit_max=0,
                ),
                InMemoryRateLimiter(),
            )
            for repository in repositories
        ]
        original = await scoped[0].put(event(0))
        assert await scoped[1].put(event(0)) == original
        await expect_capacity(scoped[1], event(1), "quarantine_bank_capacity_exceeded")
        await scoped[1].put(event(0, "bob", "beta"))
        assert (await repositories[0].stats(AT))["pending_items"] == 2
        async with databases[0].transaction(capacity_lock=True) as tx:
            await tx.execute("DELETE FROM quarantine_items")
            await tx.execute("DELETE FROM quarantine_events")
        stores = [
            QuarantineStore(
                pem,
                repository,
                QuarantineLimits(max_pending_items_per_writer=0, rate_limit_max=0),
                InMemoryRateLimiter(),
            )
            for repository in repositories
        ]
        results = await asyncio.gather(
            *(stores[index % 2].put(event(index)) for index in range(70)),
            return_exceptions=True,
        )
        rejected = [value for value in results if isinstance(value, BaseException)]
        assert len(rejected) == 6, rejected
        assert all(
            isinstance(error, HttpError)
            and error.code == "quarantine_security_event_capacity_exceeded"
            for error in rejected
        ), rejected
        assert (await repositories[1].stats(AT))["total_items"] == 64

    database = await create_database(url)
    try:
        restarted = QuarantineStore(
            pem,
            QuarantineRepository(database),
            QuarantineLimits(max_pending_items_per_writer=0, rate_limit_max=0),
            InMemoryRateLimiter(),
        )
        await expect_capacity(restarted, event(100), "quarantine_security_event_capacity_exceeded")
    finally:
        await database.close()


async def main() -> None:
    configured = os.environ["QUARANTINE_DATABASE_URL"]
    if not is_postgres(configured):
        with TemporaryDirectory() as directory:
            await verify_capacity(f"sqlite:{Path(directory) / 'audit.db'}")
        return
    schema = "audit_capacity_" + uuid.uuid4().hex
    database = PostgresDatabase(configured)
    await database.initialize()
    try:
        async with database.transaction() as tx:
            await tx.execute(f"CREATE SCHEMA {schema}")
        parts = urlsplit(configured)
        query = urlencode([*parse_qsl(parts.query), ("options", f"-csearch_path={schema}")])
        try:
            await verify_capacity(urlunsplit(parts._replace(query=query)))
        finally:
            async with database.transaction() as tx:
                await tx.execute(f"DROP SCHEMA {schema} CASCADE")
    finally:
        await database.close()


asyncio.run(main())
