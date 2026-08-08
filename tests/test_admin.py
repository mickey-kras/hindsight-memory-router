from __future__ import annotations

import pytest

from memory_router.errors import HttpError
from memory_router.registry import DEFAULT_REGISTRY
from memory_router.quarantine.admin import QuarantineAdminService, _cleanup_filter, _require_object, _require_string
from memory_router.quarantine.crypto import decrypt_envelope
from memory_router.quarantine.store import QuarantineInput
from tests.helpers import FakeHindsight, store


def err(exc: pytest.ExceptionInfo[HttpError], code: str) -> None:
    assert exc.value.code == code


@pytest.mark.asyncio
async def test_admin_queue_read_postpone_stats_cleanup_and_errors(tmp_path):
    qstore, repo, private = await store(tmp_path)
    hindsight = FakeHindsight()
    admin = QuarantineAdminService(repo, hindsight, DEFAULT_REGISTRY, max_postpones=1)
    out = await qstore.put(
        QuarantineInput(
            timestamp="2026-08-07T00:00:00.000Z",
            kind="retain_request",
            reason="suspicious_content",
            writer_id="main",
            source="application",
            dedupe_key="admin-retain",
            payload={"action":"retain","writer_id":"main","body":{"items":[{"content":"x"}]}},
        )
    )
    qid = out["quarantine_id"]
    queue = await admin.list_queue(10, 0)
    assert queue["total"] == 1 and queue["items"][0]["quarantine_id"] == qid
    item = await admin.read_item(qid)
    assert item["record"]["status"] == "pending"
    decrypted = decrypt_envelope(item["encrypted"], private).to_dict()

    bad = dict(decrypted)
    bad["payload"] = {"action":"retain","writer_id":"main","body":{"items":[{"content":"changed"}]}}
    with pytest.raises(HttpError) as exc:
        await admin.approve(qid, {"decrypted": bad})
    err(exc, "quarantine_hash_mismatch")

    postponed = await admin.postpone(qid)
    assert postponed["count"] == 1
    with pytest.raises(HttpError) as exc:
        await admin.postpone(qid)
    err(exc, "postpone_limit_reached")
    stats = await admin.stats()
    assert stats["postponed_items"] == 1 and "expired_items" not in stats
    preview = await admin.cleanup({"dry_run": True})
    assert preview["count"] == 1
    with pytest.raises(HttpError) as exc:
        await admin.cleanup({"dry_run": False})
    err(exc, "expected_count_required")
    cleaned = await admin.cleanup({"dry_run": False, "expected_count": 1})
    assert cleaned["count"] == 1
    with pytest.raises(HttpError) as exc:
        await admin.read_item(qid)
    err(exc, "quarantine_not_found")
    with pytest.raises(HttpError) as exc:
        await admin.read_item("bad")
    err(exc, "invalid_quarantine_id")
    await repo.close()


@pytest.mark.asyncio
async def test_admin_approve_retain_exact_hash_and_unknown_writer(tmp_path):
    qstore, repo, private = await store(tmp_path)
    hindsight = FakeHindsight()
    admin = QuarantineAdminService(repo, hindsight, DEFAULT_REGISTRY)
    result = await qstore.put(
        QuarantineInput(
            timestamp="2026-08-07T00:00:00.000Z",
            kind="retain_request",
            reason="suspicious_content",
            writer_id="main",
            source="application",
            dedupe_key="approve-retain",
            payload={"action":"retain","writer_id":"main","body":{"items":[{"content":"safe"}]}},
        )
    )
    qid = result["quarantine_id"]
    encrypted = (await admin.read_item(qid))["encrypted"]
    decrypted = decrypt_envelope(encrypted, private).to_dict()
    approved = await admin.approve(qid, {"decrypted": decrypted})
    assert approved == {"approved": True, "quarantine_id": qid, "target_bank": "main"}
    assert hindsight.retains and hindsight.retains[0][0] == "main"
    assert await repo.get(qid) is None

    unknown = await qstore.put(
        QuarantineInput(
            timestamp="2026-08-07T00:00:01.000Z",
            kind="retain_request",
            reason="unknown_writer",
            writer_id="ghost",
            source="application",
            dedupe_key="unknown-retain",
            payload={"action":"retain","writer_id":"ghost","body":{"items":[{"content":"safe"}]}},
        )
    )
    uqid = unknown["quarantine_id"]
    decrypted = decrypt_envelope((await admin.read_item(uqid))["encrypted"], private).to_dict()
    with pytest.raises(HttpError) as exc:
        await admin.approve(uqid, {"decrypted": decrypted})
    err(exc, "writer_not_registered")
    await repo.close()


@pytest.mark.asyncio
async def test_admin_recalled_approve_reject_and_invalid_actions(tmp_path):
    qstore, repo, private = await store(tmp_path)
    hindsight = FakeHindsight()
    admin = QuarantineAdminService(repo, hindsight, DEFAULT_REGISTRY)

    async def recalled(memory_id: str):
        res = await qstore.put(
            QuarantineInput(
                timestamp=f"2026-08-07T00:00:0{memory_id[-1]}.000Z",
                kind="recalled_memory",
                reason="recalled_suspicious_memory",
                writer_id="main",
                source="application",
                source_bank="main",
                source_memory_id=memory_id,
                source_content_sha256="a" * 64,
                payload={"action":"recalled_memory","bank_id":"main","result":{"id":memory_id,"text":"bad"}},
            )
        )
        qid = res["quarantine_id"]
        dec = decrypt_envelope((await admin.read_item(qid))["encrypted"], private).to_dict()
        return qid, dec

    qid1, dec1 = await recalled("m1")
    allowed = await admin.approve(qid1, {"decrypted": dec1})
    assert allowed["allowed"] is True
    final = await repo.get(qid1)
    assert final and final.status == "reviewed_allowed" and final.encrypted is None
    with pytest.raises(HttpError) as exc:
        await admin.read_item(qid1)
    err(exc, "quarantine_already_finalized")

    qid2, _ = await recalled("m2")
    blocked = await admin.reject(qid2)
    assert blocked["allowed"] is False
    assert hindsight.invalidations[-1][0:2] == ("main", "m2")
    assert qid2 in hindsight.invalidations[-1][2]
    assert (await repo.get(qid2)).status == "reviewed_blocked"  # type: ignore[union-attr]

    # A security event can be rejected, but never approved into memory.
    sec = await qstore.put(
        QuarantineInput(
            timestamp="2026-08-07T00:00:09.000Z",
            kind="security_event",
            reason="denied_endpoint",
            source="http",
            dedupe_key="sec",
            payload={"action":"denied_endpoint"},
        )
    )
    sqid = sec["quarantine_id"]
    sdec = decrypt_envelope((await admin.read_item(sqid))["encrypted"], private).to_dict()
    with pytest.raises(HttpError) as exc:
        await admin.approve(sqid, {"decrypted": sdec})
    err(exc, "invalid_review_action")
    assert (await admin.reject(sqid))["rejected"] is True
    await repo.close()


def test_admin_validation_helpers():
    assert _cleanup_filter({}) == {"scope": "pending"}
    assert _cleanup_filter({"scope":"all","reasons":["unknown_writer"],"older_than":"2026-01-01T00:00:00Z"})["scope"] == "all"
    for body, code in [({"scope":"x"}, "invalid_request"), ({"reasons":[1]}, "invalid_request"), ({"older_than":"nope"}, "invalid_cleanup_time")]:
        with pytest.raises(HttpError) as exc:
            _cleanup_filter(body)
        err(exc, code)
    with pytest.raises(HttpError):
        _require_object([], "x")
    with pytest.raises(HttpError):
        _require_string("", "x")
    assert _require_object({}, "x") == {}
    assert _require_string("x", "x") == "x"
