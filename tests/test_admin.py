from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from memory_router import admin as admin_module
from memory_router.canonical import sha256_hex
from memory_router.envelope import canonical_decrypted
from memory_router.errors import HttpError
from memory_router.models import WriterRegistry

QID = "q_item_0123456789abcdef"


def registry() -> WriterRegistry:
    return WriterRegistry.model_validate(
        {
            "writers": {
                "main": {
                    "role": "default",
                    "source": "application",
                    "write_bank": "main",
                    "read_banks": ["main"],
                }
            },
            "defaults": {
                "unknown_writer_action": "review_queue",
                "suspicious_content_action": "review_queue",
            },
        }
    )


def exact_item(
    kind: str, payload: object, **extra: object
) -> tuple[dict[str, object], dict[str, object]]:
    decrypted: dict[str, object] = {
        "quarantine_id": QID,
        "created_at": "2026-08-08T00:00:00.000Z",
        "reason": "suspicious_content",
        "writer_id": "main",
        "source": "http",
        "payload": payload,
    }
    item: dict[str, object] = {
        **decrypted,
        "updated_at": "2026-08-08T00:00:00.000Z",
        "kind": kind,
        "status": "pending",
        "postpone_count": 0,
        "encrypted": {"v": 1},
        "encrypted_bytes": 123,
        "sha256": sha256_hex(canonical_decrypted(decrypted)),
    }
    item.pop("payload")
    item.update(extra)
    return item, decrypted


def service(
    item: dict[str, object] | None,
) -> tuple[
    admin_module.QuarantineAdminService,
    SimpleNamespace,
    SimpleNamespace,
    SimpleNamespace,
]:
    repository = SimpleNamespace(
        get=AsyncMock(return_value=item),
        list_reviewable=AsyncMock(return_value=[]),
        stats=AsyncMock(
            return_value={
                "total_items": 1,
                "pending_items": 1,
                "postponed_items": 2,
                "reviewed_allowed_items": 3,
                "reviewed_blocked_items": 4,
                "encrypted_bytes": 5,
                "event_count": 6,
            }
        ),
    )
    hindsight = SimpleNamespace(retain=AsyncMock(), invalidate_memory=AsyncMock())
    limits = SimpleNamespace(assert_retain_bounds=Mock(), consume_retain=AsyncMock())
    return (
        admin_module.QuarantineAdminService(repository, hindsight, registry(), limits, 2, 300),
        repository,
        hindsight,
        limits,
    )


@pytest.mark.asyncio
async def test_list_read_stats_and_require_reviewable() -> None:
    item, _ = exact_item("retain_request", {})
    svc, repo, _, _ = service(item)
    assert (await svc.list_queue(10, 0))["total"] == 3
    repo.list_reviewable.assert_awaited_once()
    assert len(repo.list_reviewable.await_args.args) == 3
    read = await svc.read_item(QID)
    assert (
        "encrypted" in read
        and "encrypted" not in read["record"]
        and read["record"]["encrypted_bytes"] == 123
    )
    stats = await svc.stats()
    assert stats["event_count"] == 6 and "expired_items" not in stats
    with pytest.raises(HttpError) as bad_id:
        await svc.read_item("bad")
    assert bad_id.value.code == "invalid_quarantine_id"
    repo.get.return_value = None
    with pytest.raises(HttpError) as missing:
        await svc.read_item(QID)
    assert missing.value.status == 404
    repo.get.return_value = {**item, "status": "reviewed_allowed"}
    with pytest.raises(HttpError) as final:
        await svc.read_item(QID)
    assert final.value.code == "quarantine_already_finalized"
    repo.get.return_value = {**item, "encrypted": None}
    with pytest.raises(HttpError) as unavailable:
        await svc.read_item(QID)
    assert unavailable.value.code == "quarantine_payload_unavailable"


@pytest.mark.asyncio
async def test_expired_item_cannot_be_reviewed() -> None:
    item, _ = exact_item("retain_request", {}, expires_at="2020-01-01T00:00:00.000Z")
    svc, _, _, _ = service(item)
    with pytest.raises(HttpError) as expired:
        await svc.read_item(QID)
    assert expired.value.code == "quarantine_expired"


def test_verify_exact_validation_hash_and_metadata() -> None:
    item, decrypted = exact_item("retain_request", {})
    assert admin_module.QuarantineAdminService._verify_exact(item, decrypted) == decrypted
    with pytest.raises(HttpError) as invalid:
        admin_module.QuarantineAdminService._verify_exact(item, None)
    assert invalid.value.code == "invalid_decrypted_quarantine"
    wrong = {**decrypted, "payload": {"x": 1}}
    with pytest.raises(HttpError) as mismatch:
        admin_module.QuarantineAdminService._verify_exact(item, wrong)
    assert mismatch.value.code == "quarantine_hash_mismatch"
    altered_item = {**item, "reason": "other", "sha256": sha256_hex(canonical_decrypted(decrypted))}
    with pytest.raises(HttpError) as meta:
        admin_module.QuarantineAdminService._verify_exact(altered_item, decrypted)
    assert meta.value.code == "quarantine_metadata_mismatch"
    with pytest.raises(HttpError):
        admin_module.QuarantineAdminService._verify_exact({**item, "encrypted": None}, decrypted)


@pytest.mark.asyncio
async def test_approve_retain_success_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"action": "retain", "writer_id": "main", "body": {"items": [{"content": "ok"}]}}
    item, decrypted = exact_item("retain_request", payload)
    svc, repo, hindsight, limits = service(item)
    claim = AsyncMock(return_value=item)
    finish = AsyncMock()
    interrupt = AsyncMock()
    monkeypatch.setattr(admin_module, "claim_review", claim)
    monkeypatch.setattr(admin_module, "finish_approve_retain", finish)
    monkeypatch.setattr(admin_module, "interrupt_review", interrupt)
    result = await svc.approve(QID, {"decrypted": decrypted})
    assert result == {"approved": True, "quarantine_id": QID, "target_bank": "main"}
    limits.assert_retain_bounds.assert_called_once()
    limits.consume_retain.assert_awaited_once_with("main")
    hindsight.retain.assert_awaited_once()
    approved_body = hindsight.retain.await_args.args[1]
    assert approved_body["items"][0]["metadata"] == {
        "router_writer_id": "main",
        "router_source": "http",
        "router_decision": "approved",
        "router_target_bank": "main",
    }
    assert claim.await_args.args[4] == 300
    assert claim.await_args.kwargs == {
        "expected_sha256": item["sha256"],
        "expected_updated_at": item["updated_at"],
    }
    finish.assert_awaited_once()

    for bad_payload, code in (
        ({}, "invalid_quarantine_payload"),
        ({"action": "retain", "body": {"items": [{"content": "x"}]}}, "invalid_request"),
        (
            {"action": "retain", "writer_id": "unknown", "body": {"items": [{"content": "x"}]}},
            "writer_not_registered",
        ),
    ):
        bad_item, bad_decrypted = exact_item("retain_request", bad_payload)
        repo.get.return_value = bad_item
        with pytest.raises(HttpError) as exc:
            await svc.approve(QID, {"decrypted": bad_decrypted})
        assert exc.value.code == code

    repo.get.return_value = item
    hindsight.retain.side_effect = RuntimeError("upstream")
    with pytest.raises(RuntimeError, match="upstream"):
        await svc.approve(QID, {"decrypted": decrypted})
    interrupt.assert_awaited()


@pytest.mark.asyncio
async def test_approve_recalled_memory_claims_verified_snapshot_before_marking_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"action": "recalled_memory", "bank_id": "main", "result": {"id": "m1", "text": "ok"}}
    item, decrypted = exact_item(
        "recalled_memory", payload, source_bank="main", source_memory_id="m1"
    )
    svc, repo, _, _ = service(item)
    claim = AsyncMock(return_value=item)
    finish = AsyncMock()
    monkeypatch.setattr(admin_module, "claim_review", claim)
    monkeypatch.setattr(admin_module, "finish_approve_memory", finish)
    result = await svc.approve(QID, {"decrypted": decrypted})
    assert result["allowed"] is True and result["source_memory_id"] == "m1"
    assert claim.await_args.args[4] == 300
    assert claim.await_args.kwargs == {
        "expected_sha256": item["sha256"],
        "expected_updated_at": item["updated_at"],
    }
    finish.assert_awaited_once_with(
        repo,
        QID,
        claim.await_args.args[3],
        expected_sha256=item["sha256"],
    )

    claim.side_effect = HttpError(
        409, "quarantine_review_changed", "quarantine item changed before review could be claimed"
    )
    finish.reset_mock()
    with pytest.raises(HttpError) as changed:
        await svc.approve(QID, {"decrypted": decrypted})
    assert changed.value.code == "quarantine_review_changed"
    finish.assert_not_awaited()

    claim.side_effect = None
    bad_item, bad_decrypted = exact_item(
        "recalled_memory", {"action": "wrong"}, source_bank="main", source_memory_id="m1"
    )
    repo.get.return_value = bad_item
    with pytest.raises(HttpError) as invalid:
        await svc.approve(QID, {"decrypted": bad_decrypted})
    assert invalid.value.code == "invalid_quarantine_payload"
    mismatch_item, mismatch_dec = exact_item(
        "recalled_memory", payload, source_bank="other", source_memory_id="m1"
    )
    repo.get.return_value = mismatch_item
    with pytest.raises(HttpError) as mismatch:
        await svc.approve(QID, {"decrypted": mismatch_dec})
    assert mismatch.value.code == "quarantine_source_mismatch"

    other_item, other_dec = exact_item("security_event", {})
    repo.get.return_value = other_item
    with pytest.raises(HttpError) as action:
        await svc.approve(QID, {"decrypted": other_dec})
    assert action.value.code == "invalid_review_action"


@pytest.mark.asyncio
async def test_reject_memory_and_request_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    memory, _ = exact_item("recalled_memory", {}, source_bank="main", source_memory_id="m1")
    svc, repo, hindsight, _ = service(memory)
    claim = AsyncMock(return_value=memory)
    finish = AsyncMock()
    interrupt = AsyncMock()
    remove = AsyncMock()
    monkeypatch.setattr(admin_module, "claim_review", claim)
    monkeypatch.setattr(admin_module, "finish_reject_memory", finish)
    monkeypatch.setattr(admin_module, "interrupt_review", interrupt)
    monkeypatch.setattr(admin_module, "remove", remove)
    result = await svc.reject(QID)
    assert result["allowed"] is False
    hindsight.invalidate_memory.assert_awaited_once()
    finish.assert_awaited_once()

    repo.get.return_value = {**memory, "source_bank": None}
    with pytest.raises(HttpError) as missing:
        await svc.reject(QID)
    assert missing.value.code == "quarantine_source_missing"

    repo.get.return_value = memory
    hindsight.invalidate_memory.side_effect = RuntimeError("down")
    with pytest.raises(RuntimeError):
        await svc.reject(QID)
    interrupt.assert_awaited()

    request, _ = exact_item("retain_request", {})
    repo.get.return_value = request
    hindsight.invalidate_memory.side_effect = None
    assert (await svc.reject(QID))["rejected"] is True
    remove.assert_awaited_once()


@pytest.mark.asyncio
async def test_postpone_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    item, _ = exact_item("retain_request", {})
    svc, _, _, _ = service(item)
    postpone = AsyncMock(return_value={"postpone_count": 1})
    monkeypatch.setattr(admin_module, "postpone", postpone)
    assert (await svc.postpone(QID))["count"] == 1
    postpone.assert_awaited_once()
    assert postpone.await_args.args[3:] == (300, 2)


@pytest.mark.asyncio
async def test_cleanup_dry_run_commit_and_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    item, _ = exact_item("retain_request", {})
    svc, _, _, _ = service(item)
    preview = AsyncMock(return_value={"count": 2, "encrypted_bytes": 10})
    perform = AsyncMock(return_value={"count": 2, "encrypted_bytes": 10})
    monkeypatch.setattr(admin_module, "preview_cleanup", preview)
    monkeypatch.setattr(admin_module, "cleanup", perform)
    assert await svc.cleanup({}) == {"dry_run": True, "count": 2, "encrypted_bytes": 10}
    assert (
        await svc.cleanup(
            {
                "scope": "all",
                "dry_run": False,
                "expected_count": 2,
                "older_than": "2026-01-01T00:00:00Z",
            }
        )
    )["dry_run"] is False
    perform.assert_awaited_once()
    with pytest.raises(HttpError, match="scope"):
        await svc.cleanup({"scope": "bad"})
    with pytest.raises(HttpError) as time:
        await svc.cleanup({"older_than": "bad"})
    assert time.value.code == "invalid_cleanup_time"
    for expected in (None, True, -1, "2"):
        with pytest.raises(HttpError) as required:
            await svc.cleanup({"dry_run": False, "expected_count": expected})
        assert required.value.code == "expected_count_required"


def test_iso_now_shape() -> None:
    assert admin_module.iso_now().endswith("Z")
