from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from memory_router.canonical import canonical_json
from memory_router.db import create_database
from memory_router.envelope import decrypt_envelope
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore, _deduped_id
from memory_router.rate_limit import InMemoryRateLimiter
from memory_router.repository import QuarantineRepository
from tests.key_material import rsa_keypair
from tests.test_quarantine_store import base_input


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[QuarantineStore]:
    repository = QuarantineRepository(await create_database(f"sqlite:{tmp_path / 'identities.db'}"))
    try:
        yield QuarantineStore(
            rsa_keypair()[0], repository, QuarantineLimits(), InMemoryRateLimiter()
        )
    finally:
        await repository.close()


async def test_delimiter_collisions_store_distinct_bound_envelopes(store: QuarantineStore) -> None:
    ids = []
    for bank, memory in (("a:b", "c"), ("a", "b:c")):
        payload = {"bank": bank, "memory": memory}
        result = await store.put(
            base_input("recalled_memory", sourceBank=bank, sourceMemoryId=memory, payload=payload)
        )
        ids.append(result["quarantine_id"])
        saved = await store.repository.find_memory_state(bank, memory)
        assert saved and saved["quarantine_id"] == result["quarantine_id"]
        decrypted = decrypt_envelope(saved["encrypted"], rsa_keypair()[1])
        assert decrypted["quarantine_id"] == result["quarantine_id"]
        assert decrypted["payload"] == payload
    assert ids[0] != ids[1]
    assert all(value.startswith("q_memoryv2") for value in ids)


async def test_new_namespace_cannot_collide_with_legacy_encoded_tuple(
    store: QuarantineStore,
) -> None:
    bank, memory = "a:b", "c"
    encoded = canonical_json([bank, memory])
    legacy_bank, legacy_memory = encoded.split(":", 1)
    legacy_id = _deduped_id("memory", f"{legacy_bank}:{legacy_memory}")
    legacy_input = base_input(
        "recalled_memory", sourceBank=legacy_bank, sourceMemoryId=legacy_memory
    )
    envelope = await store._encrypt(legacy_input, legacy_id)
    legacy_item = store._build_item(legacy_input, legacy_id, envelope)
    await store.repository.store(
        legacy_item, store.capacity, mode="memory", at=legacy_input["timestamp"]
    )
    before = await store.repository.get(legacy_id)

    result = await store.put(base_input("recalled_memory", sourceBank=bank, sourceMemoryId=memory))
    assert result["quarantine_id"] == _deduped_id("memoryv2", encoded)
    assert result["quarantine_id"] != legacy_id
    assert await store.repository.get(legacy_id) == before
    saved = await store.repository.get(result["quarantine_id"])
    assert saved
    assert (
        decrypt_envelope(saved["encrypted"], rsa_keypair()[1])["quarantine_id"]
        == result["quarantine_id"]
    )


async def test_existing_legacy_tuple_keeps_id_before_encryption(store: QuarantineStore) -> None:
    original = base_input("recalled_memory", sourceBank="a:b", sourceMemoryId="c")
    legacy_id = _deduped_id("memory", "a:b:c")
    envelope = await store._encrypt(original, legacy_id)
    await store.repository.store(
        store._build_item(original, legacy_id, envelope),
        store.capacity,
        mode="memory",
        at=original["timestamp"],
    )
    updated = {**original, "timestamp": "2026-08-09T00:00:00.000Z", "payload": {"content": "new"}}
    result = await store.put(updated)
    assert result["quarantine_id"] == legacy_id
    saved = await store.repository.find_memory_state("a:b", "c")
    assert saved and saved["quarantine_id"] == legacy_id
    assert saved["created_at"] == original["timestamp"]
    assert saved["requarantine_count"] == 1
    decrypted = decrypt_envelope(saved["encrypted"], rsa_keypair()[1])
    assert decrypted["quarantine_id"] == legacy_id
    assert decrypted["payload"] == updated["payload"]
    assert await store.repository.get(store._resolve_id(updated)) is None

    # The other tuple formerly mapped to the same legacy ID, but must not reuse it.
    collision = await store.put(base_input("recalled_memory", sourceBank="a", sourceMemoryId="b:c"))
    assert collision["quarantine_id"] != legacy_id
    assert await store.repository.get(legacy_id) == saved


@pytest.mark.parametrize("legacy_first", [True, False])
async def test_mixed_memory_generations_reject_stale_envelopes_and_retry(
    store: QuarantineStore, legacy_first: bool
) -> None:
    from tests.integration.quarantine_admission import verify_memory_generation_race

    peer = QuarantineRepository(await create_database(f"sqlite:{store.repository.db.path}"))
    try:
        await verify_memory_generation_race(
            store.repository,
            peer,
            InMemoryRateLimiter(),
            InMemoryRateLimiter(),
            *rsa_keypair(),
            legacy_first=legacy_first,
        )
    finally:
        await peer.close()
