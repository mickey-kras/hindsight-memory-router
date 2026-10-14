from __future__ import annotations

import asyncio
import json
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
from memory_router.maintenance import cleanup, sweep_expired
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore
from memory_router.rate_limit import InMemoryRateLimiter
from memory_router.repository import Capacity, QuarantineRepository
from memory_router.review_repository import claim_review, finish_approve_memory, postpone

AT = "2026-09-22T00:00:00.000Z"
EXPIRES = "2026-09-23T00:00:00.000Z"


def memory(index: str, expires: str = EXPIRES) -> dict[str, Any]:
    return {
        "quarantine_id": index,
        "created_at": AT,
        "updated_at": AT,
        "kind": "recalled_memory",
        "reason": "suspicious_content",
        "writer_id": "alice",
        "bank_id": "alpha",
        "source_bank": "alpha",
        "source_memory_id": index,
        "sha256": "abc",
        "encrypted": {"data": "x"},
        "status": "pending",
        "postpone_count": 0,
        "expires_at": expires,
    }


async def verify_lifecycle(repositories: list[QuarantineRepository]) -> None:
    async with repositories[0].db.transaction() as tx:
        await tx.execute(
            """WITH RECURSIVE history(n) AS (
                SELECT 1 UNION ALL SELECT n+1 FROM history WHERE n<2000
            ) INSERT INTO quarantine_items (
                quarantine_id,created_at,updated_at,kind,reason,sha256,status,encrypted_bytes
            ) SELECT 'history-' || CAST(n AS TEXT),?,?,
                'recalled_memory','suspicious_content','abc','reviewed_blocked',0 FROM history""",
            (AT, AT),
        )
    size = len(json.dumps(memory("a")["encrypted"], separators=(",", ":")).encode())
    capacity = Capacity(1, 1, size, 1)
    admitted = await asyncio.gather(
        *(
            repositories[n % 2].store(memory(str(n)), capacity, mode="memory", at=AT)
            for n in range(8)
        ),
        return_exceptions=True,
    )
    errors = [result for result in admitted if isinstance(result, BaseException)]
    assert len(errors) == 7 and all(
        isinstance(error, HttpError) and error.code == "quarantine_capacity_exceeded"
        for error in errors
    ), errors
    winner = str(next(n for n, result in enumerate(admitted) if result is None))
    await asyncio.gather(
        *(
            repositories[n % 2].store(memory(winner), capacity, mode="memory", at=AT)
            for n in range(8)
        )
    )
    current = await repositories[0].get(winner)
    assert current and current["requarantine_count"] == 8
    await postpone(repositories[1], winner, AT)
    await claim_review(repositories[0], winner, "recalled_memory", AT)
    # In-review ciphertext remains charged even after its expiry boundary.
    try:
        await repositories[1].store(memory("next"), capacity, mode="memory", at=EXPIRES)
    except HttpError as error:
        assert error.code == "quarantine_capacity_exceeded"
    else:
        raise AssertionError("expired in-review ciphertext stopped consuming bytes")
    results = await asyncio.gather(
        finish_approve_memory(repositories[0], winner, AT),
        repositories[1].store(
            memory("next", "2027-01-01T00:00:00.000Z"), capacity, mode="memory", at=EXPIRES
        ),
        return_exceptions=True,
    )
    assert results[0] is None, results
    if isinstance(results[1], BaseException):
        assert (
            isinstance(results[1], HttpError) and results[1].code == "quarantine_capacity_exceeded"
        )
        await repositories[1].store(
            memory("next", "2027-01-01T00:00:00.000Z"), capacity, mode="memory", at=EXPIRES
        )
    assert (await cleanup(repositories[1], "all", None, None, 1, EXPIRES))["count"] == 1
    await repositories[0].store(memory("expired"), capacity, mode="memory", at=AT)
    # Replacement and expiry cleanup may win either order; both preserve one live item.
    await asyncio.gather(
        sweep_expired(repositories[0], EXPIRES),
        repositories[1].store(
            memory("expired", "2027-01-01T00:00:00.000Z"), capacity, mode="memory", at=EXPIRES
        ),
    )
    stats = await repositories[0].stats(EXPIRES)
    assert stats["pending_items"] == 1 and stats["encrypted_bytes"] == size, stats
    assert (await repositories[0].get(winner))["status"] == "reviewed_allowed"
    assert (await repositories[0].get("history-1"))["status"] == "reviewed_blocked"
    assert (await cleanup(repositories[1], "all", None, None, 1, EXPIRES))["count"] == 1
    assert (await repositories[0].stats(EXPIRES))["total_items"] == 2001
    async with repositories[0].db.transaction(capacity_lock=True) as tx:
        await tx.execute("DELETE FROM quarantine_items")
        await tx.execute("DELETE FROM quarantine_events")


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
        await verify_lifecycle(repositories)
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
        # Identity admission includes expired and zero-byte retained audit identities.
        async with databases[0].transaction() as tx:
            await tx.execute("UPDATE quarantine_items SET expires_at=?", (AT,))
            await tx.execute(
                "UPDATE quarantine_items SET encrypted_bytes=0,"
                "encrypted_envelope=NULL,status='reviewed_blocked' WHERE quarantine_id IN "
                "(SELECT quarantine_id FROM quarantine_items ORDER BY quarantine_id LIMIT 32)"
            )
        await expect_capacity(stores[1], event(100), "quarantine_security_event_capacity_exceeded")

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


if __name__ == "__main__":
    asyncio.run(main())
