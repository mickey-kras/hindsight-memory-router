from __future__ import annotations

from pathlib import Path

import pytest

from memory_router.db import SqliteDatabase, initialize_schema
from memory_router.errors import HttpError
from memory_router.repository import Capacity, QuarantineRepository
from memory_router.review_repository import (
    claim_review,
    finish_approve_retain,
    finish_reject_memory,
    interrupt_review,
    mark_memory_reviewed,
    postpone,
    recover_interrupted,
    remove,
    require_in_progress,
    require_reviewable,
)


def value(qid: str, *, kind: str = "retain_request", status: str = "pending") -> dict[str, object]:
    return {
        "quarantine_id": qid,
        "created_at": "2026-01-01T00:00:00.000Z",
        "updated_at": "2026-01-01T00:00:00.000Z",
        "kind": kind,
        "reason": "suspicious_content",
        "writer_id": "main",
        "source": "http",
        "source_bank": "main" if kind == "recalled_memory" else None,
        "source_memory_id": "m1" if kind == "recalled_memory" else None,
        "source_content_sha256": "content" if kind == "recalled_memory" else None,
        "dedupe_key": None,
        "sha256": "hash",
        "encrypted": {"v": 1},
        "status": status,
        "postpone_count": 0,
        "requarantine_count": 0,
        "expires_at": None,
    }


@pytest.fixture
async def repo(tmp_path: Path) -> QuarantineRepository:
    db = SqliteDatabase(str(tmp_path / "q.db"))
    await db.initialize()
    await initialize_schema(db)
    repository = QuarantineRepository(db)
    yield repository
    await repository.close()


async def add(repo: QuarantineRepository, item: dict[str, object]) -> None:
    await repo.store(item, Capacity(50, 50, 1_000_000), mode="id", at="2026-01-01T00:00:00.000Z")
    if item["status"] != "pending":
        async with repo.db.transaction() as tx:
            await tx.execute(
                "UPDATE quarantine_items SET status=? WHERE quarantine_id=?",
                (item["status"], item["quarantine_id"]),
            )


@pytest.mark.asyncio
async def test_postpone_mark_memory_and_remove(repo: QuarantineRepository) -> None:
    await add(repo, value("p"))
    result = await postpone(repo, "p", "2026-01-01T00:00:01.000Z")
    assert result["status"] == "postponed" and result["postpone_count"] == 1

    await add(repo, value("m", kind="recalled_memory"))
    await mark_memory_reviewed(repo, "m", "reviewed_allowed", "2026-01-01T00:00:02.000Z")
    reviewed = await repo.get("m")
    assert reviewed and reviewed["status"] == "reviewed_allowed" and reviewed["encrypted"] is None

    await add(repo, value("wrong"))
    with pytest.raises(HttpError) as invalid:
        await mark_memory_reviewed(repo, "wrong", "reviewed_allowed", "now")
    assert invalid.value.code == "invalid_review_action"

    await add(repo, value("r"))
    await remove(repo, "r", "rejected", "now")
    assert await repo.get("r") is None
    with pytest.raises(HttpError):
        await remove(repo, "missing", "rejected", "now")


@pytest.mark.asyncio
async def test_claim_interrupt_finish_approve_and_finish_reject(repo: QuarantineRepository) -> None:
    await add(repo, value("a"))
    claimed = await claim_review(repo, "a", "retain_request", "claim")
    assert claimed["status"] == "pending"
    assert (await repo.get("a"))["status"] == "review_in_progress"  # type: ignore[index]
    await interrupt_review(repo, claimed, "claim", RuntimeError("down"))
    assert (await repo.get("a"))["status"] == "pending"  # type: ignore[index]

    claimed = await claim_review(repo, "a", "retain_request", "claim2")
    await finish_approve_retain(repo, "a", "claim2", {"x": 1})
    assert await repo.get("a") is None

    await add(repo, value("m", kind="recalled_memory"))
    await claim_review(repo, "m", "recalled_memory", "claim")
    await finish_reject_memory(repo, "m", "claim")
    assert (await repo.get("m"))["status"] == "reviewed_blocked"  # type: ignore[index]


@pytest.mark.asyncio
async def test_review_guards_and_noop_interrupt(repo: QuarantineRepository) -> None:
    with pytest.raises(HttpError) as missing:
        await claim_review(repo, "missing", "retain_request", "now")
    assert missing.value.status == 404
    await add(repo, value("x", status="reviewed_allowed"))
    with pytest.raises(HttpError) as finalized:
        await claim_review(repo, "x", "retain_request", "now")
    assert finalized.value.code == "quarantine_already_finalized"

    await add(repo, value("k"))
    with pytest.raises(HttpError) as kind:
        await claim_review(repo, "k", "recalled_memory", "now")
    assert kind.value.code == "invalid_review_action"

    async with repo.db.transaction() as tx:
        with pytest.raises(HttpError):
            await require_reviewable(tx, "missing")
        with pytest.raises(HttpError):
            await require_in_progress(tx, "k", "now")

    claimed = await claim_review(repo, "k", "retain_request", "claim")
    async with repo.db.transaction() as tx:
        await tx.execute("UPDATE quarantine_items SET updated_at='other' WHERE quarantine_id='k'")
    await interrupt_review(repo, claimed, "claim", RuntimeError())
    assert (await repo.get("k"))["status"] == "review_in_progress"  # type: ignore[index]


@pytest.mark.asyncio
async def test_recover_interrupted_only_stale(repo: QuarantineRepository) -> None:
    await add(repo, value("old"))
    await claim_review(repo, "old", "retain_request", "2026-01-01T00:00:00.000Z")
    await add(repo, value("new"))
    await claim_review(repo, "new", "retain_request", "2026-01-01T00:09:30.000Z")
    await recover_interrupted(repo, "2026-01-01T00:10:00.000Z", stale_seconds=300)
    assert (await repo.get("old"))["status"] == "postponed"  # type: ignore[index]
    assert (await repo.get("new"))["status"] == "review_in_progress"  # type: ignore[index]
