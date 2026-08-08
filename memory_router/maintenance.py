from __future__ import annotations

from typing import Any

from .errors import HttpError
from .repository import QuarantineRepository, insert_event

BATCH_LIMIT = 1000
MAX_REASON_FILTERS = 6

_PREVIEW_CLEANUP_SQL = """
SELECT COUNT(*) count, COALESCE(SUM(encrypted_bytes), 0) encrypted_bytes
FROM quarantine_items
WHERE
  ((? = 'pending' AND status IN ('pending','postponed'))
    OR (? = 'all' AND status <> 'review_in_progress'))
  AND (? = 0 OR reason IN (?, ?, ?, ?, ?, ?))
  AND (? = 0 OR created_at < ?)
"""
_CLEANUP_SQL = """
SELECT quarantine_id, encrypted_bytes
FROM quarantine_items
WHERE
  ((? = 'pending' AND status IN ('pending','postponed'))
    OR (? = 'all' AND status <> 'review_in_progress'))
  AND (? = 0 OR reason IN (?, ?, ?, ?, ?, ?))
  AND (? = 0 OR created_at < ?)
"""
_CLEANUP_SQL_FOR_UPDATE = """
SELECT quarantine_id, encrypted_bytes
FROM quarantine_items
WHERE
  ((? = 'pending' AND status IN ('pending','postponed'))
    OR (? = 'all' AND status <> 'review_in_progress'))
  AND (? = 0 OR reason IN (?, ?, ?, ?, ?, ?))
  AND (? = 0 OR created_at < ?)
FOR UPDATE
"""
_SWEEP_SQL = """
SELECT quarantine_id, expires_at
FROM quarantine_items
WHERE status IN ('pending','postponed')
  AND expires_at IS NOT NULL
  AND expires_at <= ?
ORDER BY expires_at
LIMIT ?
"""
_SWEEP_SQL_FOR_UPDATE = """
SELECT quarantine_id, expires_at
FROM quarantine_items
WHERE status IN ('pending','postponed')
  AND expires_at IS NOT NULL
  AND expires_at <= ?
ORDER BY expires_at
LIMIT ?
FOR UPDATE
"""


async def preview_cleanup(
    repository: QuarantineRepository, scope: str, reasons: list[str] | None, older_than: str | None
) -> dict[str, int]:
    params = cleanup_params(scope, reasons, older_than)
    async with repository.db.transaction() as tx:
        row = await tx.fetchone(_PREVIEW_CLEANUP_SQL, params) or {}
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
    params = cleanup_params(scope, reasons, older_than)
    async with repository.db.transaction() as tx:
        query = _CLEANUP_SQL_FOR_UPDATE if tx.dialect == "postgres" else _CLEANUP_SQL
        rows = await tx.fetchall(query, params)
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
        query = _SWEEP_SQL_FOR_UPDATE if tx.dialect == "postgres" else _SWEEP_SQL
        rows = await tx.fetchall(query, (at, BATCH_LIMIT))
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


def cleanup_params(scope: str, reasons: list[str] | None, older_than: str | None) -> list[Any]:
    if scope not in {"pending", "all"}:
        raise ValueError("cleanup scope must be pending or all")
    selected = list(reasons or [])
    if len(selected) > MAX_REASON_FILTERS:
        raise ValueError("too many cleanup reasons")
    padded: list[str | None] = selected + [None] * (MAX_REASON_FILTERS - len(selected))
    return [
        scope,
        scope,
        1 if selected else 0,
        *padded,
        1 if older_than else 0,
        older_than,
    ]
