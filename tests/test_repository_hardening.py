from __future__ import annotations

from pathlib import Path

import pytest

from memory_router.db import SqliteDatabase, initialize_schema
from memory_router.errors import HttpError
from memory_router.repository import Capacity, QuarantineRepository


def quarantine_item(
    qid: str,
    *,
    dedupe: str | None = None,
    bank: str | None = None,
    memory: str | None = None,
    digest: str | None = None,
    expires: str | None = None,
) -> dict[str, object]:
    return {
        "quarantine_id": qid,
        "created_at": "2026-01-01T00:00:00.000Z",
        "updated_at": "2026-01-01T00:00:00.000Z",
        "kind": "recalled_memory" if memory else "retain_request",
        "reason": "suspicious_content",
        "writer_id": "main",
        "source": "http",
        "source_bank": bank,
        "source_memory_id": memory,
        "source_content_sha256": digest,
        "dedupe_key": dedupe,
        "sha256": "abc",
        "encrypted": {"v": 1, "data": qid},
        "status": "pending",
        "postpone_count": 0,
        "requarantine_count": 0,
        "expires_at": expires,
    }


@pytest.fixture
async def repository(tmp_path: Path) -> QuarantineRepository:
    db = SqliteDatabase(str(tmp_path / "hardening.db"))
    await db.initialize()
    await initialize_schema(db)
    repo = QuarantineRepository(db)
    yield repo
    await repo.close()


@pytest.mark.asyncio
async def test_refresh_preserves_review_state_and_original_ttl(
    repository: QuarantineRepository,
) -> None:
    capacity = Capacity(10, 10, 100_000)
    original = quarantine_item("q", dedupe="d", expires="2026-02-01T00:00:00.000Z")
    await repository.store(original, capacity, mode="request", at="2026-01-01T00:00:00.000Z")
    async with repository.db.transaction() as tx:
        await tx.execute(
            "UPDATE quarantine_items SET status='postponed', postpone_count=2 WHERE quarantine_id='q'"
        )
    replacement = quarantine_item("new", dedupe="d", expires="2027-01-01T00:00:00.000Z")
    replacement["created_at"] = "2026-01-10T00:00:00.000Z"
    replacement["updated_at"] = "2026-01-10T00:00:00.000Z"
    await repository.store(replacement, capacity, mode="request", at="2026-01-10T00:00:00.000Z")
    loaded = await repository.get("q")
    assert loaded is not None
    assert loaded["status"] == "postponed"
    assert loaded["postpone_count"] == 2
    assert loaded["created_at"] == "2026-01-01T00:00:00.000Z"
    assert loaded["expires_at"] == "2026-02-01T00:00:00.000Z"


@pytest.mark.asyncio
async def test_review_in_progress_memory_cannot_be_refreshed(
    repository: QuarantineRepository,
) -> None:
    capacity = Capacity(10, 10, 100_000)
    original = quarantine_item("q", bank="main", memory="m", digest="old")
    await repository.store(original, capacity, mode="memory", at="2026-01-01T00:00:00.000Z")
    async with repository.db.transaction() as tx:
        await tx.execute(
            "UPDATE quarantine_items SET status='review_in_progress' WHERE quarantine_id='q'"
        )
    with pytest.raises(HttpError) as review:
        await repository.store(
            quarantine_item("new", bank="main", memory="m", digest="new"),
            capacity,
            mode="memory",
            at="2026-01-01T00:00:01.000Z",
        )
    assert review.value.code == "quarantine_item_in_review"


@pytest.mark.asyncio
async def test_changed_reviewed_memory_opens_new_review(
    repository: QuarantineRepository,
) -> None:
    capacity = Capacity(10, 10, 100_000)
    original = quarantine_item("q", bank="main", memory="m", digest="old")
    await repository.store(original, capacity, mode="memory", at="2026-01-01T00:00:00.000Z")
    async with repository.db.transaction() as tx:
        await tx.execute(
            "UPDATE quarantine_items SET status='reviewed_allowed' WHERE quarantine_id='q'"
        )
    changed = quarantine_item("new", bank="main", memory="m", digest="new")
    changed["created_at"] = "2026-02-01T00:00:00.000Z"
    changed["updated_at"] = "2026-02-01T00:00:00.000Z"
    await repository.store(changed, capacity, mode="memory", at="2026-02-01T00:00:00.000Z")
    loaded = await repository.get("q")
    assert loaded is not None
    assert loaded["status"] == "pending"
    assert loaded["source_content_sha256"] == "new"


@pytest.mark.asyncio
async def test_reviewed_memory_same_digest_reopens_for_new_safety_evidence(
    repository: QuarantineRepository,
) -> None:
    capacity = Capacity(10, 10, 100_000)
    original = quarantine_item("q", bank="main", memory="m", digest="same")
    await repository.store(original, capacity, mode="memory", at="2026-01-01T00:00:00.000Z")
    async with repository.db.transaction() as tx:
        await tx.execute(
            "UPDATE quarantine_items SET status='reviewed_allowed' WHERE quarantine_id='q'"
        )
    reopened = quarantine_item("new", bank="main", memory="m", digest="same")
    reopened["created_at"] = "2026-02-01T00:00:00.000Z"
    reopened["updated_at"] = "2026-02-01T00:00:00.000Z"
    reopened["sha256"] = "new-envelope"
    await repository.store(reopened, capacity, mode="memory", at="2026-02-01T00:00:00.000Z")
    loaded = await repository.get("q")
    assert loaded is not None
    assert loaded["status"] == "pending"
    assert loaded["source_content_sha256"] == "same"
    assert loaded["sha256"] == "new-envelope"


@pytest.mark.asyncio
async def test_expired_items_are_not_reviewable(repository: QuarantineRepository) -> None:
    expired = quarantine_item("q", expires="2025-01-01T00:00:00.000Z")
    await repository.store(
        expired,
        Capacity(10, 10, 100_000),
        mode="id",
        at="2024-01-01T00:00:00.000Z",
    )
    assert await repository.list_reviewable(10, 0, "2026-01-01T00:00:00.000Z") == []
