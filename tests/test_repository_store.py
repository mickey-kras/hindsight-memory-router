from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from memory_router.config import QuarantineLimits
from memory_router.errors import HttpError
from memory_router.quarantine.crypto import decrypt_envelope
from memory_router.quarantine.repository import Capacity, NewItem, QuarantineRepository
from memory_router.quarantine.store import QuarantineInput, request_family_identity
from memory_router.rate_limits import Bucket, DistinctIdentity, InMemorySlidingWindowRateLimiter, Rule
from tests.helpers import repository, store

NOW = "2026-08-08T00:00:00.000Z"


def _new(qid: str, **overrides):
    values = dict(
        quarantine_id=qid,
        created_at=NOW,
        updated_at=NOW,
        kind="retain_request",
        reason="suspicious_content",
        writer_id="main",
        source="openclaw",
        dedupe_key=None,
        sha256="a" * 64,
        encrypted={"ciphertext_b64": "x"},
        expires_at="2026-09-07T00:00:00.000Z",
    )
    values.update(overrides)
    return NewItem(**values)


@pytest.mark.asyncio
async def test_sqlite_repository_schema_crud_stats_and_cleanup(tmp_path):
    repo = await repository(tmp_path)
    q1 = "q_20260808T000000000Z_0000000000000001"
    q2 = "q_20260808T000000000Z_0000000000000002"
    await repo.insert(_new(q1))
    await repo.insert(_new(q2, status="postponed", postpone_count=1, writer_id="dev"))
    assert (await repo.get(q1)).kind == "retain_request"
    assert await repo.find_memory_state("main", "missing") is None
    assert [item["quarantine_id"] for item in await repo.list_reviewable()] == [q1, q2]
    stats = await repo.stats()
    assert stats["total_items"] == 2
    assert stats["pending_items"] == 1
    assert stats["postponed_items"] == 1
    assert stats["event_count"] == 2

    postponed = await repo.postpone(q1, "2026-08-08T00:01:00.000Z")
    assert postponed.status == "postponed" and postponed.postpone_count == 1
    preview = await repo.preview_cleanup({"scope": "pending"})
    assert preview["count"] == 2
    with pytest.raises(HttpError) as changed:
        await repo.cleanup({"scope": "pending"}, 1, NOW)
    assert changed.value.code == "quarantine_cleanup_changed"
    removed = await repo.cleanup({"scope": "pending"}, 2, NOW)
    assert removed["count"] == 2
    assert (await repo.stats())["total_items"] == 0
    await repo.close()


@pytest.mark.asyncio
async def test_repository_capacity_writer_scopes_and_upserts(tmp_path):
    repo = await repository(tmp_path)
    cap = Capacity(2, 1, 1_000_000)
    q1 = "q_20260808T000000000Z_1000000000000001"
    q2 = "q_20260808T000000000Z_1000000000000002"
    await repo.insert(_new(q1), cap)
    with pytest.raises(HttpError) as writer_full:
        await repo.insert(_new(q2), cap)
    assert writer_full.value.code == "quarantine_writer_capacity_exceeded"

    q3 = "q_20260808T000000000Z_1000000000000003"
    await repo.insert(_new(q3, writer_id="dev"), cap)
    with pytest.raises(HttpError) as global_full:
        await repo.insert(_new("q_20260808T000000000Z_1000000000000004", writer_id="ops"), cap)
    assert global_full.value.code == "quarantine_capacity_exceeded"

    recalled = _new(
        "q_memoryaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbb",
        kind="recalled_memory",
        reason="recalled_suspicious_memory",
        source_bank="main",
        source_memory_id="m1",
        source_content_sha256="c" * 64,
        writer_id="main",
    )
    # no capacity for this focused upsert path
    await repo.upsert_recalled_memory(recalled)
    refreshed = replace(recalled, sha256="d" * 64, created_at="2026-08-08T00:02:00.000Z", updated_at="2026-08-08T00:02:00.000Z")
    await repo.upsert_recalled_memory(refreshed)
    state = await repo.find_memory_state("main", "m1")
    assert state is not None and state.sha256 == "d" * 64 and state.requarantine_count == 1
    await repo.close()


@pytest.mark.asyncio
async def test_repository_review_claim_restore_finalize_and_recovery(tmp_path):
    repo = await repository(tmp_path)
    qid = "q_20260808T000000000Z_2000000000000001"
    await repo.insert(_new(qid))
    called = False

    async def ok():
        nonlocal called
        called = True

    await repo.approve_retain(qid, "2026-08-08T00:01:00.000Z", {"x": 1}, ok)
    assert called and await repo.get(qid) is None

    q2 = "q_20260808T000000000Z_2000000000000002"
    await repo.insert(_new(q2, status="postponed", postpone_count=2))

    async def fail():
        raise RuntimeError("upstream")

    with pytest.raises(RuntimeError):
        await repo.approve_retain(q2, "2026-08-08T00:02:00.000Z", {}, fail)
    restored = await repo.get(q2)
    assert restored is not None and restored.status == "postponed" and restored.postpone_count == 2

    recalled = _new(
        "q_memorycccccccccccccccccccccccccccccccccccccccccccccccc_dddddddddddddddd",
        kind="recalled_memory",
        reason="recalled_suspicious_memory",
        source_bank="main",
        source_memory_id="m2",
        source_content_sha256="e" * 64,
    )
    await repo.upsert_recalled_memory(recalled)
    await repo.mark_memory_reviewed(recalled.quarantine_id, "reviewed_allowed", NOW)
    state = await repo.get(recalled.quarantine_id)
    assert state is not None and state.status == "reviewed_allowed" and state.encrypted is None

    stale = _new(
        "q_20260808T000000000Z_2000000000000003",
        status="review_in_progress",
        updated_at="2026-08-07T23:58:00.000Z",
    )
    await repo.insert(stale)
    await repo.recover_interrupted_reviews(NOW)
    assert (await repo.get(stale.quarantine_id)).status == "postponed"
    await repo.close()


@pytest.mark.asyncio
async def test_repository_expiry_and_event_retention(tmp_path):
    repo = await repository(tmp_path)
    qid = "q_20260808T000000000Z_3000000000000001"
    await repo.insert(_new(qid, expires_at="2026-08-07T23:00:00.000Z"))
    assert (await repo.stats())["expired_items"] == 1
    assert await repo.sweep_expired_items(NOW) == 1
    assert await repo.get(qid) is None
    # sweep emitted a cleanup event; prune old events and then adds the retention marker event.
    assert await repo.prune_events_before("2026-08-08T00:00:01.000Z", "2026-08-08T00:10:00.000Z") >= 1
    await repo.close()


@pytest.mark.asyncio
async def test_store_encrypts_dedupes_expires_and_preserves_plaintext_hash(tmp_path):
    qstore, repo, private = await store(tmp_path)
    input_ = QuarantineInput(
        timestamp=NOW,
        kind="retain_request",
        reason="suspicious_content",
        writer_id="main",
        source="openclaw",
        dedupe_key="same",
        payload={"action": "retain", "writer_id": "main", "body": {"items": [{"content": "bad"}]}},
    )
    first = await qstore.put(input_)
    second = await qstore.put(replace(input_, timestamp="2026-08-08T00:01:00.000Z"))
    assert first["quarantine_id"] == second["quarantine_id"]
    item = await repo.get(first["quarantine_id"])
    assert item is not None and item.requarantine_count == 1 and item.expires_at is not None
    decrypted = decrypt_envelope(item.encrypted, private)
    assert decrypted.payload["body"]["items"][0]["content"] == "bad"
    assert first["sha256"] != second["sha256"]  # timestamp is authenticated plaintext metadata
    await repo.close()


@pytest.mark.asyncio
async def test_store_capacity_is_507_before_rate_charge_and_request_finalized_refresh_is_409(tmp_path):
    limits = QuarantineLimits(max_pending_items=1, max_pending_items_per_writer=1, rate_limit_max=10)
    qstore, repo, _ = await store(tmp_path, limits=limits)
    one = QuarantineInput(NOW, "retain_request", "suspicious_content", {"x": 1}, writer_id="main", dedupe_key="one")
    await qstore.put(one)
    with pytest.raises(HttpError) as full:
        await qstore.put(QuarantineInput(NOW, "retain_request", "suspicious_content", {"x": 2}, writer_id="dev", dedupe_key="two"))
    assert full.value.status == 507
    qid = (await qstore.put(replace(one, timestamp="2026-08-08T00:01:00.000Z")))["quarantine_id"]
    await repo.remove(qid, "rejected", NOW)
    # finalized request identity is removed, so a future same request can be re-created; review-in-progress is the blocked case.
    await qstore.put(replace(one, timestamp="2026-08-08T00:02:00.000Z"))
    item = await repo.get(qid)
    assert item is not None
    async with repo.db.transaction() as tx:
        await tx.run("UPDATE quarantine_items SET status='review_in_progress' WHERE quarantine_id=?", (qid,))
    with pytest.raises(HttpError) as review:
        await qstore.put(replace(one, timestamp="2026-08-08T00:03:00.000Z"))
    assert review.value.code == "quarantine_request_in_review"
    await repo.close()


@pytest.mark.asyncio
async def test_in_memory_rate_limiter_atomic_buckets_distinct_and_identity_lock():
    limiter = InMemorySlidingWindowRateLimiter()
    rule = Rule(1, 1000)
    await limiter.consume("a", rule, at_ms=1000)
    with pytest.raises(HttpError):
        await limiter.consume("a", rule, at_ms=1001)
    await limiter.consume("a", rule, at_ms=2001)

    await limiter.consume_many_distinct(
        (Bucket("g", Rule(10, 1000)),),
        (DistinctIdentity("family", "one", Rule(1, 1000)),),
        at_ms=3000,
    )
    # refresh existing identity is allowed; a second distinct identity is not.
    await limiter.consume_many_distinct((), (DistinctIdentity("family", "one", Rule(1, 1000)),), at_ms=3001)
    with pytest.raises(HttpError):
        await limiter.consume_many_distinct((), (DistinctIdentity("family", "two", Rule(1, 1000)),), at_ms=3002)

    values = []
    async def operation(session):
        values.append(session)
        return 7
    assert await limiter.with_identity_lock("x", operation) == 7
    assert values == [limiter]


def test_request_family_normalizes_whitespace_order_and_shape():
    left = QuarantineInput(NOW, "retain_request", "unknown_writer", {"tags": ["B", "a"], "text": " Hello   WORLD "}, writer_id="unknown")
    right = QuarantineInput(NOW, "retain_request", "unknown_writer", {"tags": ["a", "b"], "text": "hello world"}, writer_id="unknown")
    assert request_family_identity(left) == request_family_identity(right)
    assert request_family_identity(QuarantineInput(NOW, "security_event", "auth_failed", {})) is None
