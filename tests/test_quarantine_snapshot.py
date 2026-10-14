from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.db import SqliteDatabase, initialize_schema
from memory_router.envelope import decrypt_envelope
from memory_router.errors import HttpError
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore
from memory_router.rate_limit import InMemoryRateLimiter
from memory_router.repository import QuarantineRepository
from tests.test_quarantine_concurrency import FirstBlockedWrapProvider
from tests.test_quarantine_store import base_input, public_key


@pytest.fixture
async def repository(tmp_path: Path) -> AsyncIterator[QuarantineRepository]:
    database = SqliteDatabase(str(tmp_path / "snapshots.db"))
    await database.initialize()
    await initialize_schema(database)
    try:
        yield QuarantineRepository(database)
    finally:
        await database.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("timestamp", ["2026-08-07T00:00:00.000Z", "2026-08-08T00:00:00.000Z"])
async def test_sequential_changed_evidence_succeeds_with_lagging_or_equal_clock(
    repository: QuarantineRepository, timestamp: str
) -> None:
    store = QuarantineStore(public_key(), repository, QuarantineLimits(), InMemoryRateLimiter())
    input_ = base_input(
        "recalled_memory", sourceBank="main", sourceMemoryId="m", sourceContentSha256="first"
    )
    first = await store.put(input_)
    result = await store.put(
        {**input_, "timestamp": timestamp, "sourceContentSha256": "second", "payload": {"x": 2}}
    )
    saved = await repository.get(first["quarantine_id"])
    assert saved and saved["source_content_sha256"] == "second"
    assert saved["sha256"] == result["sha256"] and saved["requarantine_count"] == 1
    assert saved["updated_at"] == timestamp


@pytest.mark.asyncio
@pytest.mark.parametrize("metadata", ["bankId", "sourceContentSha256"])
async def test_changed_snapshot_rejects_metadata_only_conflict(
    repository: QuarantineRepository, metadata: str
) -> None:
    key = public_key()
    provider = FirstBlockedWrapProvider(key)
    store = QuarantineStore(key, repository, QuarantineLimits(), InMemoryRateLimiter(), provider)
    input_ = base_input(
        "recalled_memory", sourceBank="main", sourceMemoryId="m", **{metadata: "old"}
    )
    provider.block_next = True
    older = asyncio.create_task(store.put(input_))
    try:
        await asyncio.wait_for(provider.started.wait(), 2)
        newer = await store.put({**input_, metadata: "new"})
        before = await repository.get(newer["quarantine_id"])
        assert store._decrypted(input_, newer["quarantine_id"]) == store._decrypted(
            {**input_, metadata: "new"}, newer["quarantine_id"]
        )
        provider.release.set()
        with pytest.raises(HttpError) as stale:
            await older
        assert stale.value.code == "quarantine_write_stale"
        assert await repository.get(newer["quarantine_id"]) == before
    finally:
        provider.release.set()
        await asyncio.gather(older, return_exceptions=True)


@pytest.mark.asyncio
async def test_delete_reinsert_same_revision_fields_does_not_hide_changed_envelope(
    repository: QuarantineRepository,
) -> None:
    key = public_key()
    provider = FirstBlockedWrapProvider(key)
    store = QuarantineStore(key, repository, QuarantineLimits(), InMemoryRateLimiter(), provider)
    seed = base_input("recalled_memory", sourceBank="main", sourceMemoryId="m")
    original = await store.put(seed)
    before = await repository.get(original["quarantine_id"])
    provider.block_next = True
    older = asyncio.create_task(store.put({**seed, "payload": {"content": "older"}}))
    try:
        await asyncio.wait_for(provider.started.wait(), 2)
        async with repository.db.transaction() as tx:
            await tx.execute(
                "DELETE FROM quarantine_items WHERE quarantine_id=?", (original["quarantine_id"],)
            )
        replacement = await store.put(seed)
        changed = await repository.get(replacement["quarantine_id"])
        assert before and changed
        assert before["updated_at"] == changed["updated_at"]
        assert before["sha256"] == changed["sha256"]
        assert before["requarantine_count"] == changed["requarantine_count"] == 0
        assert before["encrypted"] != changed["encrypted"]
        provider.release.set()
        with pytest.raises(HttpError) as stale:
            await older
        assert stale.value.code == "quarantine_write_stale"
        assert await repository.get(replacement["quarantine_id"]) == changed
    finally:
        provider.release.set()
        await asyncio.gather(older, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["recalled_memory", "retain_request"])
async def test_legacy_identity_is_resolved_before_encryption_and_return(
    repository: QuarantineRepository, kind: str
) -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    store = QuarantineStore(public_pem, repository, QuarantineLimits(), InMemoryRateLimiter())
    input_ = base_input(kind, dedupeKey="same", sourceBank="main", sourceMemoryId="m")
    legacy_id = "q_legacy_0123456789abcdef"
    encrypted = await store._encrypt(input_, legacy_id)
    await repository.store(
        store._build_item(input_, legacy_id, encrypted),
        store.capacity,
        mode="memory" if kind == "recalled_memory" else "request",
        at=str(input_["timestamp"]),
    )
    replacement = {**input_, "payload": {"content": "new evidence"}}
    result = await store.put(replacement)
    assert result["quarantine_id"] == legacy_id
    saved = await repository.get(legacy_id)
    assert saved and saved["sha256"] == result["sha256"]
    decrypted = decrypt_envelope(saved["encrypted"], private_pem)
    assert (
        decrypted["quarantine_id"] == legacy_id and decrypted["payload"] == replacement["payload"]
    )
    assert await repository.get(store._resolve_id(input_)) is None
