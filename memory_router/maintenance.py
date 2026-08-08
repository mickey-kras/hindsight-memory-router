from __future__ import annotations

from typing import Any

from .errors import HttpError
from .repository import QuarantineRepository, insert_event

BATCH_LIMIT = 1000


async def preview_cleanup(
    repository: QuarantineRepository, scope: str, reasons: list[str] | None, older_than: str | None
) -> dict[str, int]:
    where, params = cleanup_where(scope, reasons, older_than)
    async with repository.db.transaction() as tx:
        row = (
            await tx.fetchone(
                f"SELECT COUNT(*) count,COALESCE(SUM(encrypted_bytes),0) encrypted_bytes FROM quarantine_items {where}",
                params,
            )
            or {}
        )
    return {
        "count": int(row.get("count") or 0),
        "encrypted_bytes": int(row.get("encrypted_bytes") or 0),
    }


async def cleanup(
    repository: QuarantineRepository,
    scope: str,
    reasons: list[str] | None,
    older_than: str | None,
    expected_count: int,
    at: str,
) -> dict[str, int]:
    where, params = cleanup_where(scope, reasons, older_than)
    async with repository.db.transaction() as tx:
        suffix = " FOR UPDATE" if tx.dialect == "postgres" else ""
        rows = await tx.fetchall(
            f"SELECT quarantine_id,encrypted_bytes FROM quarantine_items {where}{suffix}", params
        )
        if len(rows) != expected_count:
            raise HttpError(
                409,
                "quarantine_cleanup_changed",
                "quarantine cleanup selection changed after preview",
            )
        total = 0
        for row in rows:
            total += int(row["encrypted_bytes"])
            await tx.execute(
                "DELETE FROM quarantine_items WHERE quarantine_id=?", (row["quarantine_id"],)
            )
            await insert_event(
                tx,
                row["quarantine_id"],
                "cleanup",
                at,
                {"scope": scope, "reasons": reasons, "older_than": older_than},
            )
        return {"count": len(rows), "encrypted_bytes": total}


async def sweep_expired(repository: QuarantineRepository, at: str) -> int:
    async with repository.db.transaction() as tx:
        suffix = " FOR UPDATE" if tx.dialect == "postgres" else ""
        rows = await tx.fetchall(
            "SELECT quarantine_id,expires_at FROM quarantine_items WHERE status IN ('pending','postponed') AND expires_at IS NOT NULL AND expires_at<=? ORDER BY expires_at LIMIT ?"
            + suffix,
            (at, BATCH_LIMIT),
        )
        for row in rows:
            await tx.execute(
                "DELETE FROM quarantine_items WHERE quarantine_id=?", (row["quarantine_id"],)
            )
            await insert_event(
                tx,
                row["quarantine_id"],
                "cleanup",
                at,
                {"reason": "expired", "expires_at": row["expires_at"]},
            )
        return len(rows)


async def prune_events_before(repository: QuarantineRepository, cutoff: str, at: str) -> int:
    async with repository.db.transaction() as tx:
        rows = await tx.fetchall(
            "SELECT event_id FROM quarantine_events WHERE occurred_at<? ORDER BY occurred_at LIMIT ?",
            (cutoff, BATCH_LIMIT),
        )
        for row in rows:
            await tx.execute("DELETE FROM quarantine_events WHERE event_id=?", (row["event_id"],))
        if rows:
            await insert_event(
                tx,
                "quarantine_retention",
                "retention_pruned",
                at,
                {"pruned_events": len(rows), "older_than": cutoff},
            )
        return len(rows)


def cleanup_where(
    scope: str, reasons: list[str] | None, older_than: str | None
) -> tuple[str, list[Any]]:
    conditions = [
        "status IN ('pending','postponed')"
        if scope == "pending"
        else "status<>'review_in_progress'"
    ]
    params: list[Any] = []
    if reasons:
        conditions.append("reason IN (" + ",".join("?" for _ in reasons) + ")")
        params.extend(reasons)
    if older_than:
        conditions.append("created_at<?")
        params.append(older_than)
    return "WHERE " + " AND ".join(conditions), params
