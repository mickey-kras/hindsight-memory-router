from __future__ import annotations

from datetime import datetime
from typing import Any

from .errors import HttpError
from .repository import QuarantineRepository, insert_event, stored

_SELECT_ITEM = "SELECT * FROM quarantine_items WHERE quarantine_id=?"
_SELECT_ITEM_FOR_UPDATE = _SELECT_ITEM + " FOR UPDATE"
_SELECT_IN_PROGRESS = "SELECT * FROM quarantine_items WHERE status='review_in_progress'"
_SELECT_IN_PROGRESS_FOR_UPDATE = _SELECT_IN_PROGRESS + " FOR UPDATE"


def _item_query(tx: Any) -> str:
    return _SELECT_ITEM_FOR_UPDATE if tx.dialect == "postgres" else _SELECT_ITEM


async def postpone(repository: QuarantineRepository, quarantine_id: str, at: str) -> dict[str, Any]:
    async with repository.db.transaction() as tx:
        item = await require_reviewable(tx, quarantine_id)
        await tx.execute(
            "UPDATE quarantine_items SET status='postponed',postpone_count=postpone_count+1,updated_at=? WHERE quarantine_id=?",
            (at, quarantine_id),
        )
        await insert_event(
            tx, quarantine_id, "postponed", at, {"postpone_count": int(item["postpone_count"]) + 1}
        )
        return stored(await tx.fetchone(_SELECT_ITEM, (quarantine_id,))) or {}


async def mark_memory_reviewed(
    repository: QuarantineRepository, quarantine_id: str, status: str, at: str
) -> None:
    async with repository.db.transaction() as tx:
        item = await require_reviewable(tx, quarantine_id)
        if item["kind"] != "recalled_memory":
            raise HttpError(
                409, "invalid_review_action", "only recalled memories can be marked reviewed"
            )
        await mark_recalled(tx, item, status, at)


async def claim_review(
    repository: QuarantineRepository, quarantine_id: str, kind: str, at: str
) -> dict[str, Any]:
    async with repository.db.transaction() as tx:
        item = stored(await tx.fetchone(_item_query(tx), (quarantine_id,)))
        if not item:
            raise HttpError(404, "quarantine_not_found", "quarantine item not found")
        if item["status"] not in {"pending", "postponed"}:
            raise HttpError(
                409, "quarantine_already_finalized", "quarantine item is not pending review"
            )
        if item["kind"] != kind:
            raise HttpError(409, "invalid_review_action", "invalid quarantine review action")
        await tx.execute(
            "UPDATE quarantine_items SET status='review_in_progress',updated_at=? WHERE quarantine_id=?",
            (at, quarantine_id),
        )
        return item


async def interrupt_review(
    repository: QuarantineRepository, claimed: dict[str, Any], at: str, error: Exception
) -> None:
    async with repository.db.transaction() as tx:
        current = stored(await tx.fetchone(_item_query(tx), (claimed["quarantine_id"],)))
        if not current or current["status"] != "review_in_progress" or current["updated_at"] != at:
            return
        await tx.execute(
            "UPDATE quarantine_items SET status=?,updated_at=? WHERE quarantine_id=?",
            (claimed["status"], at, claimed["quarantine_id"]),
        )
        await insert_event(
            tx,
            claimed["quarantine_id"],
            "review_interrupted",
            at,
            {"outcome": claimed["status"], "error": type(error).__name__},
        )


async def finish_approve_retain(
    repository: QuarantineRepository, quarantine_id: str, at: str, details: dict[str, Any]
) -> None:
    async with repository.db.transaction() as tx:
        item = await require_in_progress(tx, quarantine_id, at)
        await tx.execute(
            "DELETE FROM quarantine_items WHERE quarantine_id=?", (item["quarantine_id"],)
        )
        await insert_event(tx, quarantine_id, "approved", at, details)


async def finish_reject_memory(
    repository: QuarantineRepository, quarantine_id: str, at: str
) -> None:
    async with repository.db.transaction() as tx:
        item = await require_in_progress(tx, quarantine_id, at)
        await mark_recalled(tx, item, "reviewed_blocked", at)


async def remove(
    repository: QuarantineRepository, quarantine_id: str, event_type: str, at: str
) -> None:
    async with repository.db.transaction() as tx:
        item = stored(await tx.fetchone(_item_query(tx), (quarantine_id,)))
        if not item:
            raise HttpError(404, "quarantine_not_found", "quarantine item not found")
        await tx.execute("DELETE FROM quarantine_items WHERE quarantine_id=?", (quarantine_id,))
        await insert_event(tx, quarantine_id, event_type, at, {})


async def recover_interrupted(
    repository: QuarantineRepository, at: str, stale_seconds: int = 300
) -> None:
    now = datetime.fromisoformat(at.replace("Z", "+00:00"))
    async with repository.db.transaction() as tx:
        query = (
            _SELECT_IN_PROGRESS_FOR_UPDATE
            if tx.dialect == "postgres"
            else _SELECT_IN_PROGRESS
        )
        rows = await tx.fetchall(query)
        for row in rows:
            updated = datetime.fromisoformat(str(row["updated_at"]).replace("Z", "+00:00"))
            if (now - updated).total_seconds() < stale_seconds:
                continue
            await tx.execute(
                "UPDATE quarantine_items SET status='postponed',updated_at=? WHERE quarantine_id=? AND status='review_in_progress'",
                (at, row["quarantine_id"]),
            )
            await insert_event(
                tx,
                row["quarantine_id"],
                "review_interrupted",
                at,
                {"outcome": "postponed", "recovered": True},
            )


async def require_reviewable(tx: Any, quarantine_id: str) -> dict[str, Any]:
    item = stored(await tx.fetchone(_item_query(tx), (quarantine_id,)))
    if not item:
        raise HttpError(404, "quarantine_not_found", "quarantine item not found")
    if item["status"] not in {"pending", "postponed"}:
        raise HttpError(
            409, "quarantine_already_finalized", "quarantine item is not pending review"
        )
    return item


async def require_in_progress(tx: Any, quarantine_id: str, at: str) -> dict[str, Any]:
    item = stored(await tx.fetchone(_item_query(tx), (quarantine_id,)))
    if not item or item["status"] != "review_in_progress" or item["updated_at"] != at:
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
