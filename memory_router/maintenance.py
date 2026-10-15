from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from typing import Any, get_args

from .envelope import QuarantineReason
from .errors import HttpError
from .lifecycle import finish_before_cancelling
from .repository import (
    CLEANUP_FILTER_SQL,
    PENDING,
    REVIEWABLE_FILTER_SQL,
    QuarantineRepository,
    insert_event,
)
from .timestamps import iso_format

BATCH_LIMIT = 1000

_CLEANUP_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}"
    r"(?:\.(?P<fraction>\d+))?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)",
    re.ASCII,
)

_SWEEP_SQL = """
SELECT quarantine_id, expires_at
FROM quarantine_items
WHERE status IN ('pending','postponed')
  AND expires_at IS NOT NULL
  AND expires_at <= ?
ORDER BY expires_at
LIMIT ?
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
    *,
    actor: str | None = None,
) -> dict[str, int]:
    where, params = cleanup_params(scope, reasons, older_than)
    async with repository.db.transaction() as tx:
        rows = await tx.fetchall(
            tx.select_for_update(_cleanup_query("quarantine_id, encrypted_bytes", where)),
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
            await insert_event(tx, row["quarantine_id"], "cleanup", at, details, actor=actor)
        return {"count": len(rows), "encrypted_bytes": total}


async def sweep_expired(repository: QuarantineRepository, at: str) -> int:
    async with repository.db.transaction() as tx:
        query = tx.select_for_update(_SWEEP_SQL)
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


EXPORT_EVENT_KEYS = ("event_id", "quarantine_id", "occurred_at", "event_type", "details")

_EVENT_EXPORT_SELECT = """
SELECT event_id, quarantine_id, occurred_at, event_type, details
FROM quarantine_events
WHERE occurred_at<? ORDER BY occurred_at
LIMIT ?
"""

_EVENT_ID_SELECT = (
    "SELECT event_id FROM quarantine_events WHERE occurred_at<? ORDER BY occurred_at LIMIT ?"
)


def append_event_export(path: str, rows: list[dict[str, Any]]) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(
                json.dumps({key: str(row[key]) for key in EXPORT_EVENT_KEYS}, separators=(",", ":"))
                + "\n"
            )


async def prune_events_before(
    repository: QuarantineRepository, cutoff: str, at: str, export_path: str | None = None
) -> int:
    total = 0
    while True:
        async with repository.db.transaction() as tx:
            if export_path is None:
                rows = await tx.fetchall(_EVENT_ID_SELECT, (cutoff, BATCH_LIMIT))
            else:
                rows = await tx.fetchall(_EVENT_EXPORT_SELECT, (cutoff, BATCH_LIMIT))
                if rows:
                    await finish_before_cancelling(
                        asyncio.to_thread(append_event_export, export_path, rows)
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
    if not isinstance(scope, str) or scope not in {PENDING, "all"}:
        raise HttpError(400, "invalid_cleanup", "cleanup scope must be pending or all")
    if reasons is not None and not isinstance(reasons, list):
        raise HttpError(400, "invalid_cleanup", "cleanup reasons must be an array")
    selected = reasons or []
    if any(not isinstance(reason, str) for reason in selected):
        raise HttpError(400, "invalid_cleanup", "cleanup reasons must contain strings")
    if any(reason not in get_args(QuarantineReason) for reason in selected):
        raise HttpError(
            400, "invalid_cleanup", "cleanup reasons must be supported quarantine reasons"
        )
    clauses = [REVIEWABLE_FILTER_SQL if scope == PENDING else CLEANUP_FILTER_SQL]
    params: list[Any] = []
    if selected:
        clauses.append("reason IN (" + ",".join("?" for _ in selected) + ")")
        params.extend(selected)
    if older_than is not None:
        cutoff, has_submillisecond = _cleanup_cutoff(older_than)
        # Stored creation times are UTC milliseconds. A fractional cutoff after
        # that millisecond includes the stored instant at its truncated boundary.
        clauses.append("created_at <= ?" if has_submillisecond else "created_at < ?")
        params.append(cutoff)
    return " AND ".join(clauses), params


def _cleanup_cutoff(value: str) -> tuple[str, bool]:
    try:
        match = _CLEANUP_TIME.fullmatch(value) if isinstance(value, str) else None
        if match is None:
            raise ValueError("expected a timestamp with a timezone")
        cutoff = iso_format(datetime.fromisoformat(value.upper()))
    except (ValueError, OverflowError) as exc:
        raise HttpError(
            400,
            "invalid_cleanup_time",
            "older_than must be an ISO timestamp with a timezone (Z or +/-HH:MM)",
        ) from exc
    # Inspect all digits: datetime only retains six fractional digits.
    fraction = match.group("fraction") or ""
    return cutoff, any(digit != "0" for digit in fraction[3:])


def _cleanup_query(select: str, where: str) -> str:
    return f"SELECT {select} FROM quarantine_items WHERE {where}"  # nosec B608  # noqa: S608
