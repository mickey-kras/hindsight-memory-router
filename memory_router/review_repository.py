from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, cast

from .db import Tx
from .errors import HttpError
from .hindsight import HindsightGatewayError
from .repository import (
    POSTPONED,
    REVIEW_IN_PROGRESS,
    REVIEW_SIDE_EFFECT_COMPLETED,
    REVIEW_SIDE_EFFECT_STARTED,
    REVIEWABLE_STATUSES,
    REVIEWED_ALLOWED,
    REVIEWED_BLOCKED,
    QuarantineRepository,
    insert_event,
    is_expired,
    stored,
)
from .timestamps import parse_iso

REVIEW_STALE_SECONDS = 60
_EXPIRED_MESSAGE = "quarantine item has expired"
_NOT_FOUND_MESSAGE = "quarantine item not found"
_SELECT_ITEM = "SELECT * FROM quarantine_items WHERE quarantine_id=?"
_SELECT_IN_PROGRESS = "SELECT * FROM quarantine_items WHERE status='review_in_progress'"


def _stale(updated_at: str, at: str, stale_seconds: int = REVIEW_STALE_SECONDS) -> bool:
    try:
        updated = parse_iso(updated_at)
        current = parse_iso(at)
    except ValueError:
        return False
    return (current - updated).total_seconds() >= stale_seconds


def _assert_reviewable(item: dict[str, Any], at: str) -> None:
    if item["status"] not in REVIEWABLE_STATUSES:
        raise HttpError(
            409, "quarantine_already_finalized", "quarantine item is not pending review"
        )
    if is_expired(item, at):
        raise HttpError(409, "quarantine_expired", _EXPIRED_MESSAGE)


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


async def _mutate_review[T](
    repository: QuarantineRepository,
    quarantine_id: str,
    at: str,
    stale_seconds: int | None,
    mutation: Callable[[Tx, dict[str, object]], Awaitable[T]],
    *,
    expected_sha256: str | None = None,
    expected_updated_at: str | None = None,
) -> T:
    expired = False
    result: T
    async with repository.db.transaction() as tx:
        item = stored(await tx.fetchone(tx.select_for_update(_SELECT_ITEM), (quarantine_id,)))
        if not item:
            raise HttpError(404, "quarantine_not_found", _NOT_FOUND_MESSAGE)
        _assert_snapshot(item, expected_sha256, expected_updated_at)
        item, expired = await _recover_stale_for_action(tx, item, at, stale_seconds)
        if not expired:
            _assert_reviewable(item, at)
            result = await mutation(tx, item)
    if expired:
        raise HttpError(409, "quarantine_expired", _EXPIRED_MESSAGE)
    return result


async def postpone(
    repository: QuarantineRepository,
    quarantine_id: str,
    at: str,
    stale_seconds: int | None = None,
    max_postpones: int | None = None,
) -> dict[str, object]:
    async def apply(tx: Tx, item: dict[str, object]) -> dict[str, object]:
        count = int(cast(int, item.get("postpone_count")) or 0)
        if max_postpones is not None and count >= max_postpones:
            raise HttpError(
                409,
                "postpone_limit_reached",
                "maximum postpone count reached; approve, reject, or wait for QUARANTINE_ITEM_TTL_DAYS expiry",
            )
        await tx.execute(
            "UPDATE quarantine_items SET status='postponed',postpone_count=postpone_count+1,updated_at=? WHERE quarantine_id=?",
            (at, quarantine_id),
        )
        await insert_event(tx, quarantine_id, POSTPONED, at, {"postpone_count": count + 1})
        return stored(await tx.fetchone(_SELECT_ITEM, (quarantine_id,))) or {}

    return await _mutate_review(repository, quarantine_id, at, stale_seconds, apply)


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
    side_effect: bool = False,
    *,
    expected_sha256: str | None = None,
    expected_updated_at: str | None = None,
) -> dict[str, Any]:
    async def apply(tx: Tx, item: dict[str, object]) -> dict[str, object]:
        if item["kind"] != kind:
            raise HttpError(409, "invalid_review_action", "invalid quarantine review action")
        status = REVIEW_SIDE_EFFECT_STARTED if side_effect else REVIEW_IN_PROGRESS
        await tx.execute(
            "UPDATE quarantine_items SET status=?,updated_at=? WHERE quarantine_id=?",
            (status, at, quarantine_id),
        )
        if side_effect:
            await insert_event(
                tx,
                quarantine_id,
                REVIEW_SIDE_EFFECT_STARTED,
                at,
                {"previous_status": item["status"]},
            )
        return item

    return await _mutate_review(
        repository,
        quarantine_id,
        at,
        stale_seconds,
        apply,
        expected_sha256=expected_sha256,
        expected_updated_at=expected_updated_at,
    )


async def complete_side_effect(
    repository: QuarantineRepository,
    quarantine_id: str,
    at: str,
    *,
    expected_sha256: str | None = None,
) -> None:
    async with repository.db.transaction() as tx:
        await require_side_effect_started(tx, quarantine_id, at, expected_sha256=expected_sha256)
        await tx.execute(
            "UPDATE quarantine_items SET status='review_side_effect_completed',updated_at=? WHERE quarantine_id=?",
            (at, quarantine_id),
        )
        await insert_event(tx, quarantine_id, REVIEW_SIDE_EFFECT_COMPLETED, at, {})


async def interrupt_review(
    repository: QuarantineRepository, claimed: dict[str, Any], at: str, error: Exception
) -> None:
    async with repository.db.transaction() as tx:
        current = stored(
            await tx.fetchone(tx.select_for_update(_SELECT_ITEM), (claimed["quarantine_id"],))
        )
        if (
            not current
            or current["status"] not in {REVIEW_IN_PROGRESS, REVIEW_SIDE_EFFECT_STARTED}
            or current["updated_at"] != at
        ):
            return
        status = str(claimed["status"])
        if status not in REVIEWABLE_STATUSES:
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
        item = await require_side_effect_completed(
            tx, quarantine_id, at, expected_sha256=expected_sha256
        )
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
        await mark_recalled(tx, item, REVIEWED_ALLOWED, at)


async def finish_reject_memory(
    repository: QuarantineRepository,
    quarantine_id: str,
    at: str,
    *,
    expected_sha256: str | None = None,
) -> None:
    async with repository.db.transaction() as tx:
        item = await require_side_effect_completed(
            tx, quarantine_id, at, expected_sha256=expected_sha256
        )
        await mark_recalled(tx, item, REVIEWED_BLOCKED, at)


async def remove(
    repository: QuarantineRepository,
    quarantine_id: str,
    event_type: str,
    at: str,
    stale_seconds: int | None = None,
) -> None:
    async def apply(tx: Tx, item: dict[str, object]) -> None:
        await tx.execute(
            "DELETE FROM quarantine_items WHERE quarantine_id=?", (item["quarantine_id"],)
        )
        await insert_event(tx, quarantine_id, event_type, at, {})

    await _mutate_review(repository, quarantine_id, at, stale_seconds, apply)


async def recover_interrupted(
    repository: QuarantineRepository, at: str, stale_seconds: int = REVIEW_STALE_SECONDS
) -> None:
    async with repository.db.transaction() as tx:
        query = tx.select_for_update(_SELECT_IN_PROGRESS)
        rows = await tx.fetchall(query)
        for row in rows:
            if not _stale(str(row["updated_at"]), at, stale_seconds):
                continue
            if is_expired(row, at):
                await _expire_stale_claim(tx, row, at)
            else:
                await _restore_stale_claim(tx, row, at)


async def _recover_stale_for_action(
    tx: Tx,
    item: dict[str, Any],
    at: str,
    stale_seconds: int | None,
) -> tuple[dict[str, Any], bool]:
    if (
        stale_seconds is None
        or item["status"] != REVIEW_IN_PROGRESS
        or not _stale(str(item.get("updated_at") or ""), at, stale_seconds)
    ):
        return item, False
    if is_expired(item, at):
        await _expire_stale_claim(tx, item, at)
        return item, True
    await _restore_stale_claim(tx, item, at)
    return {**item, "status": POSTPONED, "updated_at": at}, False


async def _expire_stale_claim(tx: Tx, item: dict[str, Any], at: str) -> None:
    await tx.execute(
        "DELETE FROM quarantine_items WHERE quarantine_id=? AND status='review_in_progress'",
        (item["quarantine_id"],),
    )
    await insert_event(
        tx,
        item["quarantine_id"],
        "expired",
        at,
        {"recovered": True, "previous_status": REVIEW_IN_PROGRESS},
    )


async def _restore_stale_claim(tx: Tx, item: dict[str, Any], at: str) -> None:
    await tx.execute(
        "UPDATE quarantine_items SET status='postponed',updated_at=? WHERE quarantine_id=? AND status='review_in_progress'",
        (at, item["quarantine_id"]),
    )
    await insert_event(
        tx,
        item["quarantine_id"],
        "review_interrupted",
        at,
        {"outcome": POSTPONED, "recovered": True},
    )


async def require_reviewable(tx: Tx, quarantine_id: str, at: str) -> dict[str, Any]:
    item = stored(await tx.fetchone(tx.select_for_update(_SELECT_ITEM), (quarantine_id,)))
    if not item:
        raise HttpError(404, "quarantine_not_found", _NOT_FOUND_MESSAGE)
    _assert_reviewable(item, at)
    return item


async def require_in_progress(
    tx: Tx,
    quarantine_id: str,
    at: str,
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    return await _require_review_state(
        tx,
        quarantine_id,
        at,
        REVIEW_IN_PROGRESS,
        expected_sha256=expected_sha256,
    )


async def require_side_effect_started(
    tx: Tx,
    quarantine_id: str,
    at: str,
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    return await _require_review_state(
        tx,
        quarantine_id,
        at,
        REVIEW_SIDE_EFFECT_STARTED,
        expected_sha256=expected_sha256,
    )


async def require_side_effect_completed(
    tx: Tx,
    quarantine_id: str,
    at: str,
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    return await _require_review_state(
        tx,
        quarantine_id,
        at,
        REVIEW_SIDE_EFFECT_COMPLETED,
        expected_sha256=expected_sha256,
    )


async def _require_review_state(
    tx: Tx,
    quarantine_id: str,
    at: str,
    status: str,
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    item = stored(await tx.fetchone(tx.select_for_update(_SELECT_ITEM), (quarantine_id,)))
    if not item or item["status"] != status or item["updated_at"] != at:
        raise HttpError(
            409, "quarantine_review_changed", "quarantine item changed while review was in progress"
        )
    if expected_sha256 is not None and str(item.get("sha256")) != expected_sha256:
        raise HttpError(
            409, "quarantine_review_changed", "quarantine item changed while review was in progress"
        )
    return item


async def mark_recalled(tx: Tx, item: dict[str, Any], status: str, at: str) -> None:
    await tx.execute(
        "UPDATE quarantine_items SET status=?,encrypted_envelope=NULL,encrypted_bytes=0,updated_at=? WHERE quarantine_id=?",
        (status, at, item["quarantine_id"]),
    )
    await insert_event(
        tx,
        item["quarantine_id"],
        REVIEWED_ALLOWED if status == REVIEWED_ALLOWED else REVIEWED_BLOCKED,
        at,
        {
            "source_bank": item.get("source_bank"),
            "source_memory_id": item.get("source_memory_id"),
            "source_content_sha256": item.get("source_content_sha256"),
        },
    )
