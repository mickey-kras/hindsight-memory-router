from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import AsyncExitStack
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.db import create_backend
from memory_router.errors import HttpError
from memory_router.key_wrap import RsaOaepWrapProvider
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore
from memory_router.rate_limit import Bucket
from memory_router.repository import QuarantineRepository


class BlockedWrapProvider(RsaOaepWrapProvider):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.release = asyncio.Event()
        self.started: asyncio.Queue[None] = asyncio.Queue()
        self.block_all = True
        self.block_next = False

    async def wrap(self, dek: bytes) -> bytes:
        blocked = self.block_all or self.block_next
        self.block_next = False
        self.started.put_nowait(None)
        if blocked:
            await self.release.wait()
        return await super().wrap(dek)


async def verify() -> None:
    backend = await create_backend(os.environ["QUARANTINE_DATABASE_URL"])
    assert backend.database.dialect == "postgres" and backend.rate_limit_database is not None
    async with AsyncExitStack() as resources:
        resources.push_async_callback(backend.database.close)
        resources.push_async_callback(backend.rate_limit_database.close)
        peer_backend = await create_backend(os.environ["QUARANTINE_DATABASE_URL"])
        assert peer_backend.rate_limit_database is not None
        resources.push_async_callback(peer_backend.database.close)
        resources.push_async_callback(peer_backend.rate_limit_database.close)
        repo = QuarantineRepository(backend.database)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        pem = key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        provider = BlockedWrapProvider(pem)
        store = QuarantineStore(
            pem, repo, QuarantineLimits(rate_limit_max=0), backend.rate_limiter, provider
        )
        peer_store = QuarantineStore(
            pem,
            QuarantineRepository(peer_backend.database),
            QuarantineLimits(rate_limit_max=0),
            peer_backend.rate_limiter,
            provider,
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
            provider.block_all = False
            for equal_timestamps in (False, True):
                provider.release.clear()
                provider.block_next = True
                older_input = {
                    **request(f"reorder-{equal_timestamps}"),
                    "kind": "recalled_memory",
                    "sourceBank": prefix,
                    "sourceMemoryId": f"reorder-{equal_timestamps}",
                    "sourceContentSha256": "older",
                    "payload": {"content": "older"},
                }
                newer_input = {
                    **older_input,
                    "sourceContentSha256": "newer",
                    "payload": {"content": "newer"},
                    "timestamp": (
                        older_input["timestamp"] if equal_timestamps else "2026-10-14T00:00:01.000Z"
                    ),
                }
                older = asyncio.create_task(store.put(older_input))
                try:
                    await asyncio.wait_for(provider.started.get(), 5)
                    newer = await asyncio.wait_for(peer_store.put(newer_input), 5)
                    created.add(newer["quarantine_id"])
                    await provider.started.get()
                    before = await repo.get(newer["quarantine_id"])
                    provider.release.set()
                    try:
                        await asyncio.wait_for(older, 5)
                    except HttpError as exc:
                        assert exc.status == 409 and exc.code == "quarantine_write_stale"
                    else:
                        raise AssertionError("older wrap replaced newer evidence")
                    saved = await repo.get(newer["quarantine_id"])
                    assert saved and saved == before and saved["source_content_sha256"] == "newer"
                    assert saved["updated_at"] == newer_input["timestamp"]
                    lagging_input = {
                        **newer_input,
                        "timestamp": "2026-10-13T00:00:00.000Z",
                        "sourceContentSha256": "lagging-clock-update",
                        "payload": {"content": "subsequent genuine update"},
                    }
                    sequential = await asyncio.wait_for(store.put(lagging_input), 5)
                    await provider.started.get()
                    latest = await repo.get(sequential["quarantine_id"])
                    assert latest and latest["source_content_sha256"] == "lagging-clock-update"
                finally:
                    older.cancel()
                    await asyncio.gather(older, return_exceptions=True)
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
