from __future__ import annotations

from typing import Any

from .errors import HttpError
from .repository import QuarantineRepository, insert_event

BATCH_LIMIT = 1000

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
    where, params = cleanup_params(scope, reasons, older_than)
    async with repository.db.transaction() as tx:
        row = (
            await tx.fetchone(
                _cleanup_query(
                    "COUNT(*) count, COALESCE(SUM(encrypted_bytes), 0) encrypted_bytes", where
                ),
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
    where, params = cleanup_params(scope, reasons, older_than)
    async with repository.db.transaction() as tx:
        rows = await tx.fetchall(
            _cleanup_query(
                "quarantine_id, encrypted_bytes",
                where,
                for_update=tx.dialect == "postgres",
            ),
            params,
        )
        if len(rows) != expected_count:
            raise HttpError(
                409,
                "quarantine_cleanup_changed",
                "quarantine cleanup selection changed after preview",
            )
        total = 0
        filter_details: dict[str, Any] = {"scope": scope}
        if reasons:
            filter_details["reasons"] = reasons
        if older_than is not None:
            filter_details["older_than"] = older_than
        details = {"filter": filter_details}
        for row in rows:
            total += int(row["encrypted_bytes"])
            await tx.execute(
                "DELETE FROM quarantine_items WHERE quarantine_id=?", (row["quarantine_id"],)
            )
            await insert_event(tx, row["quarantine_id"], "cleanup", at, details)
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
    total = 0
    while True:
        async with repository.db.transaction() as tx:
            rows = await tx.fetchall(
                "SELECT event_id FROM quarantine_events WHERE occurred_at<? ORDER BY occurred_at LIMIT ?",
                (cutoff, BATCH_LIMIT),
            )
            for row in rows:
                await tx.execute(
                    "DELETE FROM quarantine_events WHERE event_id=?", (row["event_id"],)
                )
        total += len(rows)
        if len(rows) < BATCH_LIMIT:
            break
    if total:
        async with repository.db.transaction() as tx:
            await insert_event(
                tx,
                "quarantine_retention",
                "retention_pruned",
                at,
                {"pruned_events": total, "older_than": cutoff},
            )
    return total


def cleanup_params(
    scope: str, reasons: list[str] | None, older_than: str | None
) -> tuple[str, list[Any]]:
    if scope not in {"pending", "all"}:
        raise HttpError(400, "invalid_cleanup", "cleanup scope must be pending or all")
    if reasons is not None and not isinstance(reasons, list):
        raise HttpError(400, "invalid_cleanup", "cleanup reasons must be an array")
    selected = reasons or []
    if any(not isinstance(reason, str) for reason in selected):
        raise HttpError(400, "invalid_cleanup", "cleanup reasons must contain strings")
    clauses = [
        "status IN ('pending','postponed')"
        if scope == "pending"
        else "status NOT IN ('review_in_progress','reviewed_allowed','reviewed_blocked')"
    ]
    params: list[Any] = []
    if selected:
        clauses.append("reason IN (" + ",".join("?" for _ in selected) + ")")
        params.extend(selected)
    if older_than is not None:
        if not isinstance(older_than, str):
            raise HttpError(400, "invalid_cleanup", "older_than must be a string")
        clauses.append("created_at < ?")
        params.append(older_than)
    return " AND ".join(clauses), params


def _cleanup_query(select: str, where: str, *, for_update: bool = False) -> str:
    suffix = " FOR UPDATE" if for_update else ""
    return f"SELECT {select} FROM quarantine_items WHERE {where}{suffix}"  # nosec B608  # noqa: S608
