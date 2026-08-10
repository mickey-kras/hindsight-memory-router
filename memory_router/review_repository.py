from __future__ import annotations

from datetime import datetime
from typing import Any

from .errors import HttpError
from .hindsight import HindsightGatewayError
from .repository import QuarantineRepository, insert_event, stored

_REVIEW_STALE_SECONDS = 60
_SELECT_ITEM = "SELECT * FROM quarantine_items WHERE quarantine_id=?"
_SELECT_ITEM_FOR_UPDATE = _SELECT_ITEM + " FOR UPDATE"
_SELECT_IN_PROGRESS = "SELECT * FROM quarantine_items WHERE status='review_in_progress'"
_SELECT_IN_PROGRESS_FOR_UPDATE = _SELECT_IN_PROGRESS + " FOR UPDATE"


def _item_query(tx: Any) -> str:
    return _SELECT_ITEM_FOR_UPDATE if tx.dialect == "postgres" else _SELECT_ITEM


def _stale(updated_at: str, at: str, stale_seconds: int = _REVIEW_STALE_SECONDS) -> bool:
    try:
        updated = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        current = datetime.fromisoformat(at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (current - updated).total_seconds() >= stale_seconds


def _expired(item: dict[str, Any], at: str) -> bool:
    expires_at = item.get("expires_at")
    return expires_at is not None and str(expires_at) <= at


def _assert_reviewable(item: dict[str, Any], at: str) -> None:
    if item["status"] not in {"pending", "postponed"}:
        raise HttpError(
            409, "quarantine_already_finalized", "quarantine item is not pending review"
        )
    if _expired(item, at):
        raise HttpError(409, "quarantine_expired", "quarantine item has expired")


def _assert_snapshot(
    item: dict[str, Any],
    expected_sha256: str | None,
    expected_updated_at: str | None,
) -> None:
    if expected_sha256 is not None and str(item.get("sha256")) != expected_sha256:
        raise HttpError(
            409,
            "quarantine_review_changed",
            "quarantine item changed before review could be claimed",
        )
    if expected_updated_at is not None and str(item.get("updated_at")) != expected_updated_at:
        raise HttpError(
            409,
            "quarantine_review_changed",
            "quarantine item changed before review could be claimed",
        )


async def postpone(
    repository: QuarantineRepository,
    quarantine_id: str,
    at: str,
    stale_seconds: int | None = None,
    max_postpones: int | None = None,
) -> dict[str, Any]:
    expired = False
    result: dict[str, Any] = {}
    async with repository.db.transaction() as tx:
        item = stored(await tx.fetchone(_item_query(tx), (quarantine_id,)))
        if not item:
            raise HttpError(404, "quarantine_not_found", "quarantine item not found")
        item, expired = await _recover_stale_for_action(tx, item, at, stale_seconds)
        if not expired:
            _assert_reviewable(item, at)
            if max_postpones is not None and int(item.get("postpone_count") or 0) >= max_postpones:
                raise HttpError(
                    409,
                    "postpone_limit_reached",
                    "maximum postpone count reached; approve, reject, or wait for QUARANTINE_ITEM_TTL_DAYS expiry",
                )
            await tx.execute(
                "UPDATE quarantine_items SET status='postponed',postpone_count=postpone_count+1,updated_at=? WHERE quarantine_id=?",
                (at, quarantine_id),
            )
            await insert_event(
                tx,
                quarantine_id,
                "postponed",
                at,
                {"postpone_count": int(item["postpone_count"]) + 1},
            )
            result = stored(await tx.fetchone(_SELECT_ITEM, (quarantine_id,))) or {}
    if expired:
        raise HttpError(409, "quarantine_expired", "quarantine item has expired")
    return result


async def mark_memory_reviewed(
    repository: QuarantineRepository,
    quarantine_id: str,
    status: str,
    at: str,
    *,
    expected_sha256: str | None = None,
    expected_updated_at: str | None = None,
) -> None:
    async with repository.db.transaction() as tx:
        item = await require_reviewable(tx, quarantine_id, at)
        _assert_snapshot(item, expected_sha256, expected_updated_at)
        if item["kind"] != "recalled_memory":
            raise HttpError(
                409, "invalid_review_action", "only recalled memories can be marked reviewed"
            )
        await mark_recalled(tx, item, status, at)


async def claim_review(
    repository: QuarantineRepository,
    quarantine_id: str,
    kind: str,
    at: str,
    stale_seconds: int | None = None,
    *,
    expected_sha256: str | None = None,
    expected_updated_at: str | None = None,
) -> dict[str, Any]:
    expired = False
    claimed: dict[str, Any] = {}
    async with repository.db.transaction() as tx:
        item = stored(await tx.fetchone(_item_query(tx), (quarantine_id,)))
        if not item:
            raise HttpError(404, "quarantine_not_found", "quarantine item not found")
        _assert_snapshot(item, expected_sha256, expected_updated_at)
        item, expired = await _recover_stale_for_action(tx, item, at, stale_seconds)
        if not expired:
            _assert_reviewable(item, at)
            if item["kind"] != kind:
                raise HttpError(409, "invalid_review_action", "invalid quarantine review action")
            await tx.execute(
                "UPDATE quarantine_items SET status='review_in_progress',updated_at=? WHERE quarantine_id=?",
                (at, quarantine_id),
            )
            claimed = item
    if expired:
        raise HttpError(409, "quarantine_expired", "quarantine item has expired")
    return claimed


async def interrupt_review(
    repository: QuarantineRepository, claimed: dict[str, Any], at: str, error: Exception
) -> None:
    async with repository.db.transaction() as tx:
        current = stored(await tx.fetchone(_item_query(tx), (claimed["quarantine_id"],)))
        if not current or current["status"] != "review_in_progress" or current["updated_at"] != at:
            return
        status = str(claimed["status"])
        if status not in {"pending", "postponed"}:
            raise RuntimeError(f"cannot restore review to {status}")
        await tx.execute(
            "UPDATE quarantine_items SET status=?,updated_at=? WHERE quarantine_id=?",
            (status, at, claimed["quarantine_id"]),
        )
        error_kind = error.kind if isinstance(error, HindsightGatewayError) else "unknown"
        await insert_event(
            tx,
            claimed["quarantine_id"],
            "review_interrupted",
            at,
            {"outcome": "restored", "status": status, "error_kind": error_kind},
        )


async def finish_approve_retain(
    repository: QuarantineRepository,
    quarantine_id: str,
    at: str,
    details: dict[str, Any],
    *,
    expected_sha256: str | None = None,
) -> None:
    async with repository.db.transaction() as tx:
        item = await require_in_progress(tx, quarantine_id, at, expected_sha256=expected_sha256)
        await tx.execute(
            "DELETE FROM quarantine_items WHERE quarantine_id=?", (item["quarantine_id"],)
        )
        await insert_event(tx, quarantine_id, "approved", at, details)


async def finish_approve_memory(
    repository: QuarantineRepository,
    quarantine_id: str,
    at: str,
    *,
    expected_sha256: str | None = None,
) -> None:
    async with repository.db.transaction() as tx:
        item = await require_in_progress(tx, quarantine_id, at, expected_sha256=expected_sha256)
        if item["kind"] != "recalled_memory":
            raise HttpError(
                409, "invalid_review_action", "only recalled memories can be marked reviewed"
            )
        await mark_recalled(tx, item, "reviewed_allowed", at)


async def finish_reject_memory(
    repository: QuarantineRepository,
    quarantine_id: str,
    at: str,
    *,
    expected_sha256: str | None = None,
) -> None:
    async with repository.db.transaction() as tx:
        item = await require_in_progress(tx, quarantine_id, at, expected_sha256=expected_sha256)
        await mark_recalled(tx, item, "reviewed_blocked", at)


async def remove(
    repository: QuarantineRepository,
    quarantine_id: str,
    event_type: str,
    at: str,
    stale_seconds: int | None = None,
) -> None:
    expired = False
    async with repository.db.transaction() as tx:
        item = stored(await tx.fetchone(_item_query(tx), (quarantine_id,)))
        if not item:
            raise HttpError(404, "quarantine_not_found", "quarantine item not found")
        item, expired = await _recover_stale_for_action(tx, item, at, stale_seconds)
        if not expired:
            _assert_reviewable(item, at)
            await tx.execute(
                "DELETE FROM quarantine_items WHERE quarantine_id=?", (item["quarantine_id"],)
            )
            await insert_event(tx, quarantine_id, event_type, at, {})
    if expired:
        raise HttpError(409, "quarantine_expired", "quarantine item has expired")


async def recover_interrupted(
    repository: QuarantineRepository, at: str, stale_seconds: int = _REVIEW_STALE_SECONDS
) -> None:
    async with repository.db.transaction() as tx:
        query = _SELECT_IN_PROGRESS_FOR_UPDATE if tx.dialect == "postgres" else _SELECT_IN_PROGRESS
        rows = await tx.fetchall(query)
        for row in rows:
            if not _stale(str(row["updated_at"]), at, stale_seconds):
                continue
            if _expired(row, at):
                await _expire_stale_claim(tx, row, at)
            else:
                await _restore_stale_claim(tx, row, at)


async def _recover_stale_for_action(
    tx: Any,
    item: dict[str, Any],
    at: str,
    stale_seconds: int | None,
) -> tuple[dict[str, Any], bool]:
    if (
        stale_seconds is None
        or item["status"] != "review_in_progress"
        or not _stale(str(item.get("updated_at") or ""), at, stale_seconds)
    ):
        return item, False
    if _expired(item, at):
        await _expire_stale_claim(tx, item, at)
        return item, True
    await _restore_stale_claim(tx, item, at)
    return {**item, "status": "postponed", "updated_at": at}, False


async def _expire_stale_claim(tx: Any, item: dict[str, Any], at: str) -> None:
    await tx.execute(
        "DELETE FROM quarantine_items WHERE quarantine_id=? AND status='review_in_progress'",
        (item["quarantine_id"],),
    )
    await insert_event(
        tx,
        item["quarantine_id"],
        "expired",
        at,
        {"recovered": True, "previous_status": "review_in_progress"},
    )


async def _restore_stale_claim(tx: Any, item: dict[str, Any], at: str) -> None:
    await tx.execute(
        "UPDATE quarantine_items SET status='postponed',updated_at=? WHERE quarantine_id=? AND status='review_in_progress'",
        (at, item["quarantine_id"]),
    )
    await insert_event(
        tx,
        item["quarantine_id"],
        "review_interrupted",
        at,
        {"outcome": "postponed", "recovered": True},
    )


async def require_reviewable(tx: Any, quarantine_id: str, at: str) -> dict[str, Any]:
    item = stored(await tx.fetchone(_item_query(tx), (quarantine_id,)))
    if not item:
        raise HttpError(404, "quarantine_not_found", "quarantine item not found")
    _assert_reviewable(item, at)
    return item


async def require_in_progress(
    tx: Any,
    quarantine_id: str,
    at: str,
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    item = stored(await tx.fetchone(_item_query(tx), (quarantine_id,)))
    if not item or item["status"] != "review_in_progress" or item["updated_at"] != at:
        raise HttpError(
            409, "quarantine_review_changed", "quarantine item changed while review was in progress"
        )
    if expected_sha256 is not None and str(item.get("sha256")) != expected_sha256:
        raise HttpError(
            409, "quarantine_review_changed", "quarantine item changed while review was in progress"
        )
    return item


async def mark_recalled(tx: Any, item: dict[str, Any], status: str, at: str) -> None:
    await tx.execute(
        "UPDATE quarantine_items SET status=?,encrypted_envelope=NULL,encrypted_bytes=0,updated_at=? WHERE quarantine_id=?",
        (status, at, item["quarantine_id"]),
    )
    await insert_event(
        tx,
        item["quarantine_id"],
        "reviewed_allowed" if status == "reviewed_allowed" else "reviewed_blocked",
        at,
        {
            "source_bank": item.get("source_bank"),
            "source_memory_id": item.get("source_memory_id"),
            "source_content_sha256": item.get("source_content_sha256"),
        },
    )
