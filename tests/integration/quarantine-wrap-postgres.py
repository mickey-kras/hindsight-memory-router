from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import AsyncExitStack
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.db import create_backend
from memory_router.key_wrap import RsaOaepWrapProvider
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore
from memory_router.rate_limit import Bucket
from memory_router.repository import QuarantineRepository


class BlockedWrapProvider(RsaOaepWrapProvider):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.release = asyncio.Event()
        self.started: asyncio.Queue[None] = asyncio.Queue()

    async def wrap(self, dek: bytes) -> bytes:
        self.started.put_nowait(None)
        await self.release.wait()
        return await super().wrap(dek)


async def verify() -> None:
    backend = await create_backend(os.environ["QUARANTINE_DATABASE_URL"])
    assert backend.database.dialect == "postgres" and backend.rate_limit_database is not None
    async with AsyncExitStack() as resources:
        resources.push_async_callback(backend.database.close)
        resources.push_async_callback(backend.rate_limit_database.close)
        repo = QuarantineRepository(backend.database)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        pem = key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        provider = BlockedWrapProvider(pem)
        store = QuarantineStore(
            pem, repo, QuarantineLimits(rate_limit_max=0), backend.rate_limiter, provider
        )
        prefix = f"wrap-smoke-{uuid.uuid4().hex}"

        def request(identity: str) -> dict[str, Any]:
            return {
                "timestamp": "2026-10-14T00:00:00.000Z",
                "kind": "retain_request",
                "reason": "suspicious_content",
                "writerId": prefix,
                "dedupeKey": f"{prefix}-{identity}",
                "payload": {"items": [{"content": "wrap concurrency smoke"}]},
            }

        created: set[str] = set()

        async def write(identity: str) -> dict[str, str]:
            result = await store.put(request(identity))
            created.add(result["quarantine_id"])
            return result

        async def blocked_writes(identities: list[str]) -> list[dict[str, str]]:
            provider.release.clear()
            tasks = [asyncio.create_task(write(identity)) for identity in identities]
            try:
                for _ in tasks:
                    await asyncio.wait_for(provider.started.get(), 5)
                await asyncio.wait_for(
                    backend.rate_limiter.consume_many([Bucket(prefix, 10, 60_000)]), 2
                )
                provider.release.set()
                return await asyncio.wait_for(asyncio.gather(*tasks), 5)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        try:
            # All five shared limiter connections must remain available while wrapping blocks.
            distinct = await blocked_writes([str(i) for i in range(5)])
            assert len({result["quarantine_id"] for result in distinct}) == 5
            # Both wraps can proceed; their short database critical sections still dedupe.
            repeated = await blocked_writes(["same", "same"])
            assert repeated[0] == repeated[1]
            saved = await repo.get(repeated[0]["quarantine_id"])
            assert saved and saved["requarantine_count"] == 1
        finally:
            async with backend.database.transaction(capacity_lock=True) as tx:
                for quarantine_id in created:
                    await tx.execute(
                        "DELETE FROM quarantine_items WHERE quarantine_id=?", (quarantine_id,)
                    )
                    await tx.execute(
                        "DELETE FROM quarantine_events WHERE quarantine_id=?", (quarantine_id,)
                    )


asyncio.run(verify())
