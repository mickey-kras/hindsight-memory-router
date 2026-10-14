from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from memory_router.db import SqliteDatabase, initialize_schema
from memory_router.errors import HttpError
from memory_router.key_wrap import RsaOaepWrapProvider
from memory_router.maintenance import sweep_expired
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore
from memory_router.rate_limit import Bucket, InMemoryRateLimiter, PostgresRateLimiter
from memory_router.repository import QuarantineRepository
from memory_router.review_repository import claim_review
from tests.test_quarantine_store import FakePostgresDatabase, FakePostgresTx, base_input, public_key


class PooledLimiterDatabase(FakePostgresDatabase):
    def __init__(self) -> None:
        super().__init__()
        self.slots = asyncio.Semaphore(5)
        self.checked_out = 0

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[FakePostgresTx]:
        async with self.slots:
            self.checked_out += 1
            try:
                async with super().transaction() as tx:
                    yield tx
            finally:
                self.checked_out -= 1


class BlockedWrapProvider(RsaOaepWrapProvider):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.release = asyncio.Event()
        self.started: asyncio.Queue[None] = asyncio.Queue()
        self.active = 0
        self.maximum_active = 0

    async def wrap(self, dek: bytes) -> bytes:
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        self.started.put_nowait(None)
        try:
            await self.release.wait()
            return await super().wrap(dek)
        finally:
            self.active -= 1


class FirstBlockedWrapProvider(RsaOaepWrapProvider):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.block_next = False
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def wrap(self, dek: bytes) -> bytes:
        if self.block_next:
            self.block_next = False
            self.started.set()
            await self.release.wait()
        return await super().wrap(dek)


@pytest.fixture
async def repository(tmp_path: Path) -> AsyncIterator[QuarantineRepository]:
    database = SqliteDatabase(str(tmp_path / "concurrency.db"))
    await database.initialize()
    await initialize_schema(database)
    repo = QuarantineRepository(database)
    try:
        yield repo
    finally:
        await repo.close()


@pytest.mark.asyncio
async def test_blocked_wrapping_leaves_postgres_pool_available_for_unrelated_admission() -> None:
    database = PooledLimiterDatabase()
    limiter = PostgresRateLimiter(database)
    repo = SimpleNamespace(
        get=AsyncMock(return_value=None),
        find_request_state=AsyncMock(return_value=None),
        store=AsyncMock(),
    )
    key = public_key()
    provider = BlockedWrapProvider(key)
    store = QuarantineStore(
        key, repo, QuarantineLimits(distinct_family_limit_max=0), limiter, provider
    )
    writes = [asyncio.create_task(store.put(base_input(dedupeKey=str(i)))) for i in range(5)]
    try:
        for _ in writes:
            await asyncio.wait_for(provider.started.get(), timeout=2)
        # Admission shares the five-connection limiter pool, but needs no wrap.
        await asyncio.wait_for(limiter.consume_many([Bucket("unrelated-admission", 1, 60_000)]), 1)
        assert database.checked_out == 0
        assert provider.active == 5
        assert len(database.state["events"]) == 11
        repo.store.assert_not_awaited()
    finally:
        provider.release.set()
        await asyncio.gather(*writes)
    assert repo.store.await_count == 5


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["retain_request", "recalled_memory", "security_event"])
async def test_concurrent_same_identity_writes_dedupe_atomically(
    repository: QuarantineRepository, kind: str
) -> None:
    key = public_key()
    provider = BlockedWrapProvider(key)
    limiter = InMemoryRateLimiter()
    store = QuarantineStore(
        key, repository, QuarantineLimits(max_pending_items=1), limiter, provider
    )
    input_ = base_input(kind, dedupeKey="same", sourceBank="main", sourceMemoryId="m")
    writes = [asyncio.create_task(store.put(input_)) for _ in range(2)]
    try:
        for _ in writes:
            await asyncio.wait_for(provider.started.get(), 2)
        assert len(limiter.events["quarantine-writes"]) == 2
    finally:
        provider.release.set()
    results = await asyncio.gather(*writes)
    assert results[0] == results[1]
    saved = await repository.get(results[0]["quarantine_id"])
    assert saved and saved["requarantine_count"] == 1
    assert saved["sha256"] == results[0]["sha256"]
    stats = await repository.stats(str(input_["timestamp"]))
    assert stats["total_items"] == stats["pending_items"] == 1
    assert stats["event_count"] == 2
    assert not limiter.locks


@pytest.mark.asyncio
@pytest.mark.parametrize("side_effect", [False, True])
async def test_review_claim_during_wrapping_is_preserved(
    repository: QuarantineRepository, side_effect: bool
) -> None:
    key = public_key()
    provider = BlockedWrapProvider(key)
    provider.release.set()
    store = QuarantineStore(key, repository, QuarantineLimits(), InMemoryRateLimiter(), provider)
    original = await store.put(base_input(dedupeKey="same"))
    await provider.started.get()
    provider.release.clear()
    write = asyncio.create_task(
        store.put(base_input(dedupeKey="same", payload={"items": [{"content": "changed"}]}))
    )
    try:
        await asyncio.wait_for(provider.started.get(), 2)
        await claim_review(
            repository,
            original["quarantine_id"],
            "retain_request",
            "2026-08-08T00:00:01.000Z",
            side_effect=side_effect,
        )
    finally:
        provider.release.set()
    with pytest.raises(HttpError) as reviewed:
        await write
    assert reviewed.value.code == "quarantine_request_in_review"
    saved = await repository.get(original["quarantine_id"])
    assert saved and saved["sha256"] == original["sha256"]
    assert saved["status"] == (
        "review_side_effect_started" if side_effect else "review_in_progress"
    )
    assert saved["requarantine_count"] == 0


@pytest.mark.asyncio
async def test_review_completion_after_final_read_is_rejected_atomically(
    repository: QuarantineRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = public_key()
    provider = BlockedWrapProvider(key)
    provider.release.set()
    store = QuarantineStore(key, repository, QuarantineLimits(), InMemoryRateLimiter(), provider)
    original = await store.put(base_input(dedupeKey="same"))
    await provider.started.get()
    provider.release.clear()
    write = asyncio.create_task(store.put(base_input(dedupeKey="same")))
    get = repository.get

    async def finish_after_read(quarantine_id: str) -> dict[str, object] | None:
        snapshot = await get(quarantine_id)
        async with repository.db.transaction() as tx:
            await tx.execute(
                "UPDATE quarantine_items SET status='reviewed_allowed' WHERE quarantine_id=?",
                (quarantine_id,),
            )
        return snapshot

    try:
        await asyncio.wait_for(provider.started.get(), 2)
        monkeypatch.setattr(repository, "get", finish_after_read)
    finally:
        provider.release.set()
    with pytest.raises(HttpError) as reviewed:
        await write
    assert reviewed.value.code == "quarantine_request_in_review"
    saved = await get(original["quarantine_id"])
    assert saved and saved["status"] == "reviewed_allowed"
    assert saved["sha256"] == original["sha256"] and saved["requarantine_count"] == 0


@pytest.mark.asyncio
async def test_capacity_is_checked_after_concurrent_wrapping(
    repository: QuarantineRepository,
) -> None:
    key = public_key()
    provider = BlockedWrapProvider(key)
    limiter = InMemoryRateLimiter()
    store = QuarantineStore(
        key, repository, QuarantineLimits(max_pending_items=1), limiter, provider
    )
    writes = [asyncio.create_task(store.put(base_input(dedupeKey=str(i)))) for i in range(2)]
    try:
        for _ in writes:
            await asyncio.wait_for(provider.started.get(), 2)
    finally:
        provider.release.set()
    results = await asyncio.gather(*writes, return_exceptions=True)
    errors = [result for result in results if isinstance(result, HttpError)]
    assert len(errors) == 1 and errors[0].code == "quarantine_capacity_exceeded"
    assert sum(isinstance(result, dict) for result in results) == 1
    stats = await repository.stats("2026-08-08T00:00:00.000Z")
    assert stats["total_items"] == stats["pending_items"] == stats["event_count"] == 1
    assert len(limiter.events["quarantine-writes"]) == 2


@pytest.mark.asyncio
async def test_sweep_during_wrapping_preserves_the_original_attempt_charge(
    repository: QuarantineRepository,
) -> None:
    key = public_key()
    provider = BlockedWrapProvider(key)
    provider.release.set()
    limiter = InMemoryRateLimiter()
    store = QuarantineStore(key, repository, QuarantineLimits(item_ttl_days=1), limiter, provider)
    original = await store.put(base_input(dedupeKey="same"))
    await provider.started.get()
    provider.release.clear()
    write = asyncio.create_task(
        store.put(base_input(dedupeKey="same", timestamp="2026-08-10T00:00:00.000Z"))
    )
    try:
        await asyncio.wait_for(provider.started.get(), 2)
        assert await sweep_expired(repository, "2026-08-10T00:00:00.000Z") == 1
        assert await repository.get(original["quarantine_id"]) is None
    finally:
        provider.release.set()
    result = await write
    saved = await repository.get(result["quarantine_id"])
    assert saved and saved["requarantine_count"] == 0
    assert saved["created_at"] == "2026-08-10T00:00:00.000Z"
    assert len(limiter.events["quarantine-writes"]) == 1
    assert len(limiter.events["quarantine-requarantine-ops"]) == 1


@pytest.mark.asyncio
async def test_active_and_waiting_wrap_cancellation_release_slots_and_keep_attempt_quotas() -> None:
    repo = SimpleNamespace(
        get=AsyncMock(return_value=None),
        find_request_state=AsyncMock(return_value=None),
        store=AsyncMock(),
    )
    key = public_key()
    provider = BlockedWrapProvider(key)
    limiter = InMemoryRateLimiter()
    store = QuarantineStore(
        key, repo, QuarantineLimits(distinct_family_limit_max=0), limiter, provider
    )
    writes = [asyncio.create_task(store.put(base_input(dedupeKey=str(i)))) for i in range(7)]
    try:
        for _ in range(5):
            await asyncio.wait_for(provider.started.get(), 2)
        assert provider.active == 5
        assert len(limiter.events["quarantine-writes"]) == 7
        # Cancel both a queued caller and one inside its provider, including repeat cancellation.
        writes[-1].cancel()
        writes[-1].cancel()
        writes[0].cancel()
        writes[0].cancel()
        await asyncio.gather(writes[-1], writes[0], return_exceptions=True)
        await asyncio.wait_for(provider.started.get(), 2)
        assert provider.active == provider.maximum_active == 5
        assert not limiter.locks
        repo.store.assert_not_awaited()
    finally:
        provider.release.set()
        results = await asyncio.gather(*writes, return_exceptions=True)
    assert sum(isinstance(result, asyncio.CancelledError) for result in results) == 2
    assert repo.store.await_count == 5
    assert provider.active == 0
    assert len(limiter.events["quarantine-writes"]) == 7
    # All five permits remain usable after cancelling holders and waiters.
    provider.release.clear()
    replacements = [
        asyncio.create_task(store.put(base_input(dedupeKey=f"replacement-{i}"))) for i in range(5)
    ]
    try:
        for _ in replacements:
            await asyncio.wait_for(provider.started.get(), 2)
        assert provider.active == 5
    finally:
        provider.release.set()
        await asyncio.gather(*replacements)


@pytest.mark.asyncio
@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("different_stores", [False, True])
@pytest.mark.parametrize("equal_timestamps", [False, True])
async def test_slower_wrap_cannot_overwrite_newer_recalled_evidence(
    repository: QuarantineRepository,
    existing: bool,
    different_stores: bool,
    equal_timestamps: bool,
) -> None:
    key = public_key()
    provider = FirstBlockedWrapProvider(key)
    limiter = InMemoryRateLimiter()
    store = QuarantineStore(key, repository, QuarantineLimits(), limiter, provider)
    peer_database = None
    newer_store = store
    if different_stores:
        assert isinstance(repository.db, SqliteDatabase)
        peer_database = SqliteDatabase(repository.db.path)
        await peer_database.initialize()
        newer_store = QuarantineStore(
            key,
            QuarantineRepository(peer_database),
            QuarantineLimits(),
            InMemoryRateLimiter(),
            provider,
        )

    def evidence(digest: str, timestamp: str) -> dict[str, object]:
        return base_input(
            "recalled_memory",
            sourceBank="main",
            sourceMemoryId="m",
            sourceContentSha256=digest,
            payload={"content": digest},
            timestamp=timestamp,
        )

    older_timestamp = "2026-08-09T00:00:00.000Z"
    newer_timestamp = older_timestamp if equal_timestamps else "2026-08-10T00:00:00.000Z"
    if existing:
        await store.put(evidence("seed", "2026-08-08T00:00:00.000Z"))
    provider.block_next = True
    older = asyncio.create_task(store.put(evidence("older", older_timestamp)))
    try:
        await asyncio.wait_for(provider.started.wait(), 2)
        newer = await asyncio.wait_for(newer_store.put(evidence("newer", newer_timestamp)), 2)
        before = await repository.get(newer["quarantine_id"])
        provider.release.set()
        with pytest.raises(HttpError) as stale:
            await asyncio.wait_for(older, 2)
        assert stale.value.status == 409 and stale.value.code == "quarantine_write_stale"
        saved = await repository.get(newer["quarantine_id"])
        assert saved == before
        assert saved and saved["source_content_sha256"] == "newer"
        assert saved["sha256"] == newer["sha256"]
        assert saved["updated_at"] == newer_timestamp
        assert saved["requarantine_count"] == int(existing)
        stats = await repository.stats(newer_timestamp)
        assert stats["pending_items"] == 1 and stats["event_count"] == 1 + int(existing)
        charge_key = "quarantine-requarantine-ops" if existing else "quarantine-writes"
        assert limiter.events[charge_key]
        assert not limiter.locks
    finally:
        provider.release.set()
        await asyncio.gather(older, return_exceptions=True)
        if peer_database is not None:
            await peer_database.close()
