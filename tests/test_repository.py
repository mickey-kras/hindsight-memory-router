from __future__ import annotations

import json
from pathlib import Path

import pytest

from memory_router.db import SqliteDatabase, initialize_schema
from memory_router.errors import HttpError
from memory_router.repository import (
    Capacity,
    QuarantineRepository,
    _expired,
    _same_scope,
    _summary,
    stored,
)


def item(
    qid: str,
    *,
    writer: str | None = "main",
    reason: str = "suspicious_content",
    status: str = "pending",
    dedupe: str | None = None,
    bank: str | None = None,
    memory: str | None = None,
    expires: str | None = None,
) -> dict[str, object]:
    return {
        "quarantine_id": qid,
        "created_at": "2026-01-01T00:00:00.000Z",
        "updated_at": "2026-01-01T00:00:00.000Z",
        "kind": "retain_request",
        "reason": reason,
        "writer_id": writer,
        "source": "http",
        "source_bank": bank,
        "source_memory_id": memory,
        "source_content_sha256": None,
        "dedupe_key": dedupe,
        "sha256": "abc",
        "encrypted": {"v": 1, "data": qid},
        "status": status,
        "postpone_count": 0,
        "requarantine_count": 0,
        "expires_at": expires,
    }


@pytest.fixture
async def repository(tmp_path: Path) -> QuarantineRepository:
    db = SqliteDatabase(str(tmp_path / "q.db"))
    await db.initialize()
    await initialize_schema(db)
    repo = QuarantineRepository(db)
    yield repo
    await repo.close()


def test_stored_summary_scope_and_expiry_helpers() -> None:
    assert stored(None) is None
    row = {
        "encrypted_envelope": '{"v":1}',
        "postpone_count": None,
        "requarantine_count": "2",
        "quarantine_id": "q",
        "status": "pending",
    }
    converted = stored(row)
    assert (
        converted
        and converted["encrypted"] == {"v": 1}
        and converted["postpone_count"] == 0
        and converted["requarantine_count"] == 2
    )
    assert _summary({"quarantine_id": "q", "status": "pending", "reason": None}) == {
        "quarantine_id": "q",
        "status": "pending",
    }
    assert _expired({"status": "pending", "expires_at": "a"}, "b")
    assert not _expired({"status": "reviewed_allowed", "expires_at": "a"}, "b")
    assert not _same_scope({"kind": "security_event"}, {"kind": "security_event"})
    assert _same_scope(
        {"kind": "x", "reason": "unknown_writer"}, {"kind": "y", "reason": "unknown_writer"}
    )
    assert not _same_scope({"reason": "unknown_writer"}, {"reason": "other"})
    assert _same_scope({"writer_id": "a"}, {"writer_id": "a"})
    assert not _same_scope({"writer_id": "a"}, {"writer_id": "b"})
    assert _same_scope({"kind": "x"}, {"kind": "x"})


@pytest.mark.asyncio
async def test_repository_store_get_refresh_list_stats_and_memory_lookup(
    repository: QuarantineRepository,
) -> None:
    capacity = Capacity(10, 10, 100_000)
    first = item("q1", dedupe="d1")
    await repository.store(first, capacity, mode="request", at="2026-01-01T00:00:00.000Z")
    loaded = await repository.get("q1")
    assert loaded and loaded["encrypted"]["data"] == "q1"
    assert await repository.get("missing") is None
    assert len(await repository.list_reviewable(10, 0, "2026-01-01T00:00:01.000Z")) == 1
    stats = await repository.stats("2026-01-01T00:00:01.000Z")
    assert stats["total_items"] == 1 and stats["pending_items"] == 1 and stats["event_count"] == 1

    refreshed = item("ignored", dedupe="d1")
    refreshed["sha256"] = "new"
    refreshed["encrypted"] = {"v": 2}
    await repository.store(refreshed, capacity, mode="request", at="2026-01-01T00:00:01.000Z")
    loaded = await repository.get("q1")
    assert loaded and loaded["requarantine_count"] == 1 and loaded["sha256"] == "new"

    memory_item = item("m1", bank="main", memory="mem1")
    await repository.store(memory_item, capacity, mode="memory", at="2026-01-01T00:00:02.000Z")
    assert (await repository.find_memory_state("main", "mem1"))["quarantine_id"] == "m1"  # type: ignore[index]

    id_item = item("id1")
    await repository.store(id_item, capacity, mode="id", at="2026-01-01T00:00:03.000Z")
    id_item["encrypted"] = {"v": 3}
    await repository.store(id_item, capacity, mode="id", at="2026-01-01T00:00:04.000Z")
    assert (await repository.get("id1"))["requarantine_count"] == 1  # type: ignore[index]
    await repository.ping()


@pytest.mark.asyncio
async def test_list_reviewable_has_stable_tiebreaker_and_complete_summary(
    repository: QuarantineRepository,
) -> None:
    capacity = Capacity(10, 10, 100_000)
    for qid in ("q_b", "q_a"):
        value = item(qid, expires="2027-01-01T00:00:00.000Z")
        await repository.store(value, capacity, mode="id", at="2026-01-01T00:00:00.000Z")

    rows = await repository.list_reviewable(10, 0, "2026-01-02T00:00:00.000Z")
    assert [row["quarantine_id"] for row in rows] == ["q_a", "q_b"]
    assert rows[0]["encrypted_bytes"] > 0
    assert rows[0]["expires_at"] == "2027-01-01T00:00:00.000Z"


@pytest.mark.asyncio
async def test_reviewed_request_dedupe_does_not_reopen(repository: QuarantineRepository) -> None:
    capacity = Capacity(10, 10, 100_000)
    original = item("q", dedupe="d")
    await repository.store(original, capacity, mode="request", at="now")
    async with repository.db.transaction() as tx:
        await tx.execute(
            "UPDATE quarantine_items SET status='reviewed_allowed' WHERE quarantine_id='q'"
        )
    replacement = item("new", dedupe="d")
    replacement["sha256"] = "changed"
    await repository.store(replacement, capacity, mode="request", at="later")
    loaded = await repository.get("q")
    assert loaded and loaded["status"] == "reviewed_allowed" and loaded["sha256"] == "abc"


@pytest.mark.asyncio
async def test_capacity_global_bytes_writer_and_expired_replacement(
    repository: QuarantineRepository,
) -> None:
    roomy = Capacity(10, 10, 100_000)
    await repository.store(item("a", writer="w"), roomy, mode="id", at="2026-01-01T00:00:00.000Z")
    with pytest.raises(HttpError) as global_cap:
        await repository.store(
            item("b", writer="x"),
            Capacity(1, 10, 100_000),
            mode="id",
            at="2026-01-01T00:00:01.000Z",
        )
    assert global_cap.value.code == "quarantine_capacity_exceeded"
    with pytest.raises(HttpError) as writer_cap:
        await repository.store(
            item("b", writer="w"),
            Capacity(10, 1, 100_000),
            mode="id",
            at="2026-01-01T00:00:01.000Z",
        )
    assert writer_cap.value.code == "quarantine_writer_capacity_exceeded"
    with pytest.raises(HttpError) as bytes_cap:
        await repository.store(
            item("b", writer="x"),
            Capacity(10, 10, 1),
            mode="id",
            at="2026-01-01T00:00:01.000Z",
        )
    assert bytes_cap.value.code == "quarantine_capacity_exceeded"

    expired = item("expired", writer="expired-w", expires="2025-01-01T00:00:00.000Z")
    await repository.store(expired, roomy, mode="id", at="2024-01-01T00:00:00.000Z")
    await repository.store(
        expired, Capacity(2, 1, 100_000), mode="id", at="2026-01-01T00:00:00.000Z"
    )


@pytest.mark.asyncio
async def test_unknown_writer_rows_do_not_consume_registered_writer_scope(
    repository: QuarantineRepository,
) -> None:
    at = "2026-01-01T00:00:00.000Z"
    capacity = Capacity(10, 1, 100_000)
    await repository.store(
        item("unknown", writer="w", reason="unknown_writer"), capacity, mode="id", at=at
    )
    await repository.store(item("known", writer="w"), capacity, mode="id", at=at)
    loaded = await repository.get("known")
    assert loaded and loaded["reason"] == "suspicious_content"


@pytest.mark.asyncio
async def test_encrypted_bytes_use_unescaped_utf8(repository: QuarantineRepository) -> None:
    value = item("unicode")
    value["encrypted"] = {"v": 1, "data": "é"}
    await repository.store(
        value, Capacity(10, 10, 100_000), mode="id", at="2026-01-01T00:00:00.000Z"
    )
    loaded = await repository.get("unicode")
    assert loaded is not None
    expected = len(
        json.dumps(value["encrypted"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    assert loaded["encrypted_bytes"] == expected


@pytest.mark.asyncio
async def test_stats_classifies_statuses_and_expiry(repository: QuarantineRepository) -> None:
    cap = Capacity(20, 20, 100_000)
    for qid, status, expires in (
        ("p", "postponed", None),
        ("e", "pending", "2020-01-01T00:00:00.000Z"),
        ("a", "reviewed_allowed", None),
        ("b", "reviewed_blocked", None),
    ):
        value = item(qid, writer=qid, expires=expires)
        await repository.store(value, cap, mode="id", at="2019-01-01T00:00:00.000Z")
        async with repository.db.transaction() as tx:
            await tx.execute(
                "UPDATE quarantine_items SET status=? WHERE quarantine_id=?", (status, qid)
            )
    stats = await repository.stats("2026-01-01T00:00:00.000Z")
    assert stats["postponed_items"] == 1
    assert stats["expired_items"] == 1
    assert stats["reviewed_allowed_items"] == 1
    assert stats["reviewed_blocked_items"] == 1
