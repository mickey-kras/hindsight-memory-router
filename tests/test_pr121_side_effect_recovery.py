from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from memory_router import admin as admin_module
from memory_router.canonical import sha256_hex
from memory_router.envelope import canonical_decrypted
from memory_router.hindsight import HindsightGatewayError
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


def retain_item(status: str = "pending") -> tuple[dict[str, object], dict[str, object]]:
    payload = {
        "action": "retain",
        "writer_id": "main",
        "body": {"items": [{"content": "ok"}]},
    }
    decrypted: dict[str, object] = {
        "quarantine_id": QID,
        "created_at": "2026-08-08T00:00:00.000Z",
        "reason": "suspicious_content",
        "writer_id": "main",
        "source": "http",
        "payload": payload,
    }
    item: dict[str, object] = {
        "quarantine_id": QID,
        "created_at": decrypted["created_at"],
        "updated_at": "2026-08-08T00:00:01.000Z",
        "reason": decrypted["reason"],
        "writer_id": decrypted["writer_id"],
        "source": decrypted["source"],
        "kind": "retain_request",
        "status": status,
        "postpone_count": 0,
        "encrypted": {"v": 1},
        "sha256": sha256_hex(canonical_decrypted(decrypted)),
    }
    return item, decrypted


def recalled_item(status: str = "pending") -> dict[str, object]:
    return {
        "quarantine_id": QID,
        "created_at": "2026-08-08T00:00:00.000Z",
        "updated_at": "2026-08-08T00:00:01.000Z",
        "reason": "suspicious_content",
        "writer_id": "main",
        "source": "http",
        "kind": "recalled_memory",
        "status": status,
        "postpone_count": 0,
        "encrypted": {"v": 1},
        "sha256": "hash",
        "source_bank": "main",
        "source_memory_id": "m1",
    }


def service(
    item: dict[str, object],
) -> tuple[admin_module.QuarantineAdminService, SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    repository = SimpleNamespace(get=AsyncMock(return_value=item))
    hindsight = SimpleNamespace(retain=AsyncMock(), invalidate_memory=AsyncMock())
    limits = SimpleNamespace(assert_retain_bounds=Mock(), consume_retain=AsyncMock())
    return (
        admin_module.QuarantineAdminService(repository, hindsight, registry(), limits, 2, 300),
        repository,
        hindsight,
        limits,
    )


@pytest.mark.asyncio
async def test_retain_upstream_failure_restores_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item, decrypted = retain_item()
    svc, _, hindsight, _ = service(item)
    claim = AsyncMock(return_value=item)
    complete = AsyncMock()
    finish = AsyncMock()
    interrupt = AsyncMock()
    monkeypatch.setattr(admin_module, "claim_review", claim)
    monkeypatch.setattr(admin_module, "complete_side_effect", complete)
    monkeypatch.setattr(admin_module, "finish_approve_retain", finish)
    monkeypatch.setattr(admin_module, "interrupt_review", interrupt)
    hindsight.retain.side_effect = RuntimeError("upstream")

    with pytest.raises(RuntimeError, match="upstream"):
        await svc.approve(QID, {"decrypted": decrypted})

    interrupt.assert_awaited_once()
    complete.assert_not_awaited()
    finish.assert_not_awaited()


@pytest.mark.asyncio
async def test_retain_ambiguous_timeout_is_not_restored_for_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item, decrypted = retain_item()
    svc, _, hindsight, _ = service(item)
    claim = AsyncMock(return_value=item)
    complete = AsyncMock()
    finish = AsyncMock()
    interrupt = AsyncMock()
    monkeypatch.setattr(admin_module, "claim_review", claim)
    monkeypatch.setattr(admin_module, "complete_side_effect", complete)
    monkeypatch.setattr(admin_module, "finish_approve_retain", finish)
    monkeypatch.setattr(admin_module, "interrupt_review", interrupt)
    hindsight.retain.side_effect = HindsightGatewayError(
        "timeout", operation="retain", method="POST", timeout_ms=10_000
    )

    with pytest.raises(HindsightGatewayError) as exc:
        await svc.approve(QID, {"decrypted": decrypted})

    assert exc.value.kind == "timeout"
    interrupt.assert_not_awaited()
    complete.assert_not_awaited()
    finish.assert_not_awaited()


@pytest.mark.asyncio
async def test_retain_finish_failure_retries_without_replaying_upstream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pending, decrypted = retain_item()
    completed = {**pending, "status": "review_side_effect_completed"}
    svc, repository, hindsight, limits = service(pending)
    repository.get.side_effect = [pending, completed]
    claim = AsyncMock(return_value=pending)
    complete = AsyncMock()
    finish = AsyncMock(side_effect=[RuntimeError("db finish"), None])
    interrupt = AsyncMock()
    monkeypatch.setattr(admin_module, "claim_review", claim)
    monkeypatch.setattr(admin_module, "complete_side_effect", complete)
    monkeypatch.setattr(admin_module, "finish_approve_retain", finish)
    monkeypatch.setattr(admin_module, "interrupt_review", interrupt)

    with pytest.raises(RuntimeError, match="db finish"):
        await svc.approve(QID, {"decrypted": decrypted})
    result = await svc.approve(QID, {"decrypted": decrypted})

    assert result["approved"] is True
    assert hindsight.retain.await_count == 1
    assert limits.consume_retain.await_count == 1
    assert claim.await_count == 1
    assert complete.await_count == 1
    assert finish.await_count == 2
    interrupt.assert_not_awaited()


@pytest.mark.asyncio
async def test_reject_finish_failure_retries_without_replaying_invalidation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pending = recalled_item()
    completed = {**pending, "status": "review_side_effect_completed"}
    svc, repository, hindsight, _ = service(pending)
    repository.get.side_effect = [pending, completed]
    claim = AsyncMock(return_value=pending)
    complete = AsyncMock()
    finish = AsyncMock(side_effect=[RuntimeError("db finish"), None])
    interrupt = AsyncMock()
    monkeypatch.setattr(admin_module, "claim_review", claim)
    monkeypatch.setattr(admin_module, "complete_side_effect", complete)
    monkeypatch.setattr(admin_module, "finish_reject_memory", finish)
    monkeypatch.setattr(admin_module, "interrupt_review", interrupt)

    with pytest.raises(RuntimeError, match="db finish"):
        await svc.reject(QID)
    result = await svc.reject(QID)

    assert result["allowed"] is False
    assert hindsight.invalidate_memory.await_count == 1
    assert claim.await_count == 1
    assert complete.await_count == 1
    assert finish.await_count == 2
    interrupt.assert_not_awaited()
