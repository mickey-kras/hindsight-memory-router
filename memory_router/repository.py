from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from .db import Database, Tx
from .errors import HttpError

SECURITY_EVENT_IDENTITY_LIMIT = 64

PENDING = "pending"
POSTPONED = "postponed"
REVIEW_IN_PROGRESS = "review_in_progress"
REVIEW_SIDE_EFFECT_STARTED = "review_side_effect_started"
REVIEW_SIDE_EFFECT_COMPLETED = "review_side_effect_completed"
REVIEWED_ALLOWED = "reviewed_allowed"
REVIEWED_BLOCKED = "reviewed_blocked"
REVIEWABLE_STATUSES = frozenset({PENDING, POSTPONED})
IN_REVIEW_STATUSES = frozenset(
    {REVIEW_IN_PROGRESS, REVIEW_SIDE_EFFECT_STARTED, REVIEW_SIDE_EFFECT_COMPLETED}
)
FINAL_STATUSES = frozenset({REVIEWED_ALLOWED, REVIEWED_BLOCKED})
CLEANUP_FILTER_SQL = (
    "status NOT IN ("
    + ",".join(
        repr(status)
        for status in (
            PENDING,
            POSTPONED,
            REVIEW_IN_PROGRESS,
            REVIEW_SIDE_EFFECT_STARTED,
            REVIEW_SIDE_EFFECT_COMPLETED,
            REVIEWED_ALLOWED,
            REVIEWED_BLOCKED,
        )
        if status in IN_REVIEW_STATUSES | FINAL_STATUSES
    )
    + ")"
)
REVIEWABLE_FILTER_SQL = (
    "status IN (" + ",".join(repr(status) for status in (PENDING, POSTPONED)) + ")"
)

STAT_KEYS = (
    "total_items",
    "pending_items",
    "postponed_items",
    "review_side_effect_started_items",
    "expired_items",
    "reviewed_allowed_items",
    "reviewed_blocked_items",
    "encrypted_bytes",
    "event_count",
)

_MEMORY_SELECT = "SELECT * FROM quarantine_items WHERE source_bank=? AND source_memory_id=?"
_REQUEST_SELECT = "SELECT * FROM quarantine_items WHERE dedupe_key=?"
_ID_SELECT = "SELECT * FROM quarantine_items WHERE quarantine_id=?"
_PENDING_SCOPE_PREFIX = (
    "SELECT COUNT(*) count FROM quarantine_items "
    "WHERE status IN ('pending','postponed') "
    "AND NOT(expires_at IS NOT NULL AND expires_at<=?) AND "
)


@dataclass(slots=True)
class Capacity:
    max_pending_items: int
    max_pending_items_per_writer: int
    max_encrypted_bytes: int
    max_pending_items_per_bank: int = 0


@dataclass(frozen=True, slots=True)
class QueueFilter:
    bank_id: str | None = None
    bank_ids: tuple[str, ...] | None = None
    writer_id: str | None = None
    principal_id: str | None = None
    kind: str | None = None
    status: str | None = None

    def active(self) -> bool:
        return any(
            value is not None
            for value in (
                self.bank_id,
                self.bank_ids,
                self.writer_id,
                self.principal_id,
                self.kind,
                self.status,
            )
        )

    def with_bank_scope(self, bank_ids: tuple[str, ...]) -> QueueFilter:
        return QueueFilter(
            bank_ids=bank_ids,
            writer_id=self.writer_id,
            principal_id=self.principal_id,
            kind=self.kind,
            status=self.status,
        )


QUEUE_FILTER_PARAMS = ("bank_id", "writer_id", "principal_id", "kind", "status")
QUEUE_KINDS = frozenset({"retain_request", "recall_request", "recalled_memory", "security_event"})
QUEUE_STATUSES = frozenset(
    {PENDING, POSTPONED, REVIEW_SIDE_EFFECT_STARTED, REVIEWED_ALLOWED, REVIEWED_BLOCKED}
)


def parse_queue_filter(params: Any) -> QueueFilter:
    values: dict[str, str] = {}
    for name in QUEUE_FILTER_PARAMS:
        entries = params.getlist(name)
        if len(entries) > 1:
            raise HttpError(400, "invalid_query", f"{name} is invalid")
        if entries:
            values[name] = entries[0]
    if values.get("kind") is not None and values["kind"] not in QUEUE_KINDS:
        raise HttpError(400, "invalid_query", "kind is invalid")
    if values.get("status") is not None and values["status"] not in QUEUE_STATUSES:
        raise HttpError(400, "invalid_query", "status is invalid")
    return QueueFilter(
        bank_id=values.get("bank_id"),
        writer_id=values.get("writer_id"),
        principal_id=values.get("principal_id"),
        kind=values.get("kind"),
        status=values.get("status"),
    )


def _filter_clause(filter_: QueueFilter) -> tuple[str, list[Any]]:
    clause = ""
    params: list[Any] = []
    conditions: list[str] = []
    if filter_.bank_id is not None:
        conditions.append("bank_id=?")
        params.append(filter_.bank_id)
    if filter_.bank_ids is not None:
        if not filter_.bank_ids:
            conditions.append("1=0")
        else:
            conditions.append("bank_id IN (" + ",".join("?" for _ in filter_.bank_ids) + ")")
            params.extend(filter_.bank_ids)
    if filter_.writer_id is not None:
        conditions.append("writer_id=?")
        params.append(filter_.writer_id)
    if filter_.principal_id is not None:
        conditions.append("writer_id=?")
        params.append(filter_.principal_id)
    if filter_.kind is not None:
        conditions.append("kind=?")
        params.append(filter_.kind)
    if filter_.status is not None:
        conditions.append("status=?")
        params.append(filter_.status)
    if conditions:
        clause = " AND " + " AND ".join(conditions)
    return clause, params


def stored(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    envelope = result.pop("encrypted_envelope", None)
    result["encrypted"] = json.loads(str(envelope)) if envelope is not None else None
    result["postpone_count"] = int(result.get("postpone_count") or 0)
    result["requarantine_count"] = int(result.get("requarantine_count") or 0)
    return result


async def insert_event(
    tx: Tx,
    quarantine_id: str,
    event_type: str,
    at: str,
    details: dict[str, Any] | None = None,
    *,
    actor: str | None = None,
) -> None:
    payload = dict(details) if details else {}
    if actor is not None:
        payload["actor"] = actor
    await tx.execute(
        "INSERT INTO quarantine_events(event_id,quarantine_id,occurred_at,event_type,details) VALUES(?,?,?,?,?)",
        (
            str(uuid.uuid4()),
            quarantine_id,
            at,
            event_type,
            json.dumps(payload, separators=(",", ":")),
        ),
    )


class QuarantineRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def ping(self) -> None:
        await self.db.ping()

    async def close(self) -> None:
        await self.db.close()

    async def get(self, quarantine_id: str) -> dict[str, Any] | None:
        async with self.db.transaction() as tx:
            return stored(await tx.fetchone(_ID_SELECT, (quarantine_id,)))

    async def find_memory_state(self, bank_id: str, memory_id: str) -> dict[str, Any] | None:
        async with self.db.transaction() as tx:
            return stored(await tx.fetchone(_MEMORY_SELECT, (bank_id, memory_id)))

    async def list_reviewable(
        self, limit: int, offset: int, at: str, filter_: QueueFilter | None = None
    ) -> list[dict[str, Any]]:
        clause, params = _filter_clause(filter_) if filter_ is not None else ("", [])
        statement = (
            "SELECT * FROM quarantine_items WHERE status IN ('pending','postponed','review_side_effect_started') "  # nosec B608  # noqa: S608
            "AND NOT(expires_at IS NOT NULL AND expires_at<=?)"
            + clause
            + " ORDER BY created_at ASC, quarantine_id ASC LIMIT ? OFFSET ?"
        )
        async with self.db.transaction() as tx:
            rows = await tx.fetchall(statement, (at, *params, limit, offset))
        return [_summary(stored(row) or {}) for row in rows]

    async def count_reviewable(self, at: str, filter_: QueueFilter) -> int:
        clause, params = _filter_clause(filter_)
        statement = (
            "SELECT COUNT(*) count FROM quarantine_items "  # nosec B608  # noqa: S608
            "WHERE status IN ('pending','postponed','review_side_effect_started') "
            "AND NOT(expires_at IS NOT NULL AND expires_at<=?)" + clause
        )
        async with self.db.transaction() as tx:
            row = await tx.fetchone(statement, (at, *params))
        return int((row or {}).get("count") or 0)

    async def stats(self, at: str) -> dict[str, int]:
        async with self.db.transaction() as tx:
            row = (
                await tx.fetchone(
                    """SELECT COUNT(*) total_items,
              SUM(CASE WHEN status='pending' AND NOT(expires_at IS NOT NULL AND expires_at<=?) THEN 1 ELSE 0 END) pending_items,
              SUM(CASE WHEN status='postponed' AND NOT(expires_at IS NOT NULL AND expires_at<=?) THEN 1 ELSE 0 END) postponed_items,
              SUM(CASE WHEN status='review_side_effect_started' AND NOT(expires_at IS NOT NULL AND expires_at<=?) THEN 1 ELSE 0 END) review_side_effect_started_items,
              SUM(CASE WHEN status IN ('pending','postponed') AND expires_at IS NOT NULL AND expires_at<=? THEN 1 ELSE 0 END) expired_items,
              SUM(CASE WHEN status='reviewed_allowed' THEN 1 ELSE 0 END) reviewed_allowed_items,
              SUM(CASE WHEN status='reviewed_blocked' THEN 1 ELSE 0 END) reviewed_blocked_items,
              COALESCE(SUM(CASE WHEN status IN ('pending','postponed') AND expires_at IS NOT NULL AND expires_at<=? THEN 0 ELSE encrypted_bytes END),0) encrypted_bytes FROM quarantine_items""",
                    (at, at, at, at, at),
                )
                or {}
            )
            events = await tx.fetchone("SELECT COUNT(*) event_count FROM quarantine_events") or {}
        return {key: int(row.get(key) or 0) for key in STAT_KEYS if key != "event_count"} | {
            "event_count": int(events.get("event_count") or 0)
        }

    async def bank_stats(
        self, at: str, bank_ids: tuple[str, ...] | None = None
    ) -> list[dict[str, Any]]:
        clause = ""
        params: list[Any] = [at, at, at]
        if bank_ids is not None:
            if not bank_ids:
                return []
            clause = " AND bank_id IN (" + ",".join("?" for _ in bank_ids) + ")"
            params.extend(bank_ids)
        statement = (
            """SELECT bank_id,
              COUNT(*) total_items,
              SUM(CASE WHEN status='pending' AND NOT(expires_at IS NOT NULL AND expires_at<=?) THEN 1 ELSE 0 END) pending_items,
              SUM(CASE WHEN status='postponed' AND NOT(expires_at IS NOT NULL AND expires_at<=?) THEN 1 ELSE 0 END) postponed_items,
              COALESCE(SUM(CASE WHEN status IN ('pending','postponed') AND expires_at IS NOT NULL AND expires_at<=? THEN 0 ELSE encrypted_bytes END),0) encrypted_bytes
              FROM quarantine_items WHERE bank_id IS NOT NULL"""  # nosec B608  # noqa: S608
            + clause
            + " GROUP BY bank_id ORDER BY bank_id ASC"
        )
        async with self.db.transaction() as tx:
            rows = await tx.fetchall(statement, params)
        return [
            {
                "bank_id": str(row["bank_id"]),
                "total_items": int(row.get("total_items") or 0),
                "pending_items": int(row.get("pending_items") or 0),
                "postponed_items": int(row.get("postponed_items") or 0),
                "encrypted_bytes": int(row.get("encrypted_bytes") or 0),
            }
            for row in rows
        ]

    async def store(self, item: dict[str, Any], capacity: Capacity, *, mode: str, at: str) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            existing = await self._find_existing(tx, item, mode)
            if existing and existing["status"] in IN_REVIEW_STATUSES:
                raise HttpError(
                    409,
                    "quarantine_item_in_review",
                    "matching quarantine item is already being reviewed",
                )
            await self._assert_capacity(tx, item, existing, capacity, at)
            if existing:
                if _expired(existing, at):
                    await self._reopen_expired(tx, existing["quarantine_id"], item)
                    return
                if mode == "request" and existing["status"] not in REVIEWABLE_STATUSES:
                    return
                if mode == "memory" and existing["status"] == REVIEWED_ALLOWED:
                    await self._reopen_reviewed_memory(
                        tx,
                        existing["quarantine_id"],
                        item,
                        content_changed=existing.get("source_content_sha256")
                        != item.get("source_content_sha256"),
                    )
                    return
                await self._refresh(
                    tx,
                    existing["quarantine_id"],
                    item,
                    int(existing.get("requarantine_count") or 0) + 1,
                )
            else:
                await self.insert_item(tx, item)

    async def _find_existing(
        self, tx: Tx, item: dict[str, Any], mode: str
    ) -> dict[str, Any] | None:
        if mode == "memory":
            query = tx.select_for_update(_MEMORY_SELECT)
            row = await tx.fetchone(query, (item["source_bank"], item["source_memory_id"]))
        elif mode == "request":
            query = tx.select_for_update(_REQUEST_SELECT)
            row = await tx.fetchone(query, (item["dedupe_key"],))
        else:
            query = tx.select_for_update(_ID_SELECT)
            row = await tx.fetchone(query, (item["quarantine_id"],))
        return stored(row)

    async def insert_item(self, tx: Tx, item: dict[str, Any]) -> None:
        envelope = json.dumps(item["encrypted"], separators=(",", ":"), ensure_ascii=False)
        await tx.execute(
            """INSERT INTO quarantine_items(quarantine_id,created_at,updated_at,kind,reason,writer_id,source,source_bank,source_memory_id,source_content_sha256,dedupe_key,sha256,encrypted_envelope,encrypted_bytes,status,postpone_count,requarantine_count,expires_at,bank_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            _params(item, envelope),
        )
        await insert_event(
            tx,
            item["quarantine_id"],
            "quarantined",
            item["created_at"],
            {"kind": item["kind"], "reason": item["reason"], "sha256": item["sha256"]},
        )

    async def _refresh(self, tx: Tx, quarantine_id: str, item: dict[str, Any], count: int) -> None:
        envelope = json.dumps(item["encrypted"], separators=(",", ":"), ensure_ascii=False)
        await tx.execute(
            """UPDATE quarantine_items SET updated_at=?,kind=?,reason=?,writer_id=?,source=?,source_bank=?,source_memory_id=?,source_content_sha256=?,dedupe_key=?,sha256=?,encrypted_envelope=?,encrypted_bytes=?,requarantine_count=requarantine_count+1,bank_id=? WHERE quarantine_id=?""",
            (
                item["updated_at"],
                item["kind"],
                item["reason"],
                item.get("writer_id"),
                item.get("source"),
                item.get("source_bank"),
                item.get("source_memory_id"),
                item.get("source_content_sha256"),
                item.get("dedupe_key"),
                item["sha256"],
                envelope,
                len(envelope.encode("utf-8")),
                item.get("bank_id"),
                quarantine_id,
            ),
        )
        if item["reason"] != "auth_failed":
            await insert_event(
                tx,
                quarantine_id,
                "requarantined",
                item["updated_at"],
                {
                    "kind": item["kind"],
                    "reason": item["reason"],
                    "sha256": item["sha256"],
                    "requarantine_count": count,
                },
            )

    async def _reopen_expired(self, tx: Tx, quarantine_id: str, item: dict[str, Any]) -> None:
        envelope = json.dumps(item["encrypted"], separators=(",", ":"), ensure_ascii=False)
        await tx.execute(
            """UPDATE quarantine_items SET created_at=?,updated_at=?,kind=?,reason=?,writer_id=?,source=?,source_bank=?,source_memory_id=?,source_content_sha256=?,dedupe_key=?,sha256=?,encrypted_envelope=?,encrypted_bytes=?,status='pending',postpone_count=0,requarantine_count=requarantine_count+1,expires_at=?,bank_id=? WHERE quarantine_id=?""",
            (
                item["created_at"],
                item["updated_at"],
                item["kind"],
                item["reason"],
                item.get("writer_id"),
                item.get("source"),
                item.get("source_bank"),
                item.get("source_memory_id"),
                item.get("source_content_sha256"),
                item.get("dedupe_key"),
                item["sha256"],
                envelope,
                len(envelope.encode("utf-8")),
                item.get("expires_at"),
                item.get("bank_id"),
                quarantine_id,
            ),
        )
        await insert_event(
            tx,
            quarantine_id,
            "requarantined",
            item["updated_at"],
            {
                "kind": item["kind"],
                "reason": item["reason"],
                "sha256": item["sha256"],
                "expired": True,
            },
        )

    async def _reopen_reviewed_memory(
        self,
        tx: Tx,
        quarantine_id: str,
        item: dict[str, Any],
        *,
        content_changed: bool,
    ) -> None:
        envelope = json.dumps(item["encrypted"], separators=(",", ":"), ensure_ascii=False)
        await tx.execute(
            """UPDATE quarantine_items SET created_at=?,updated_at=?,reason=?,writer_id=?,source=?,source_content_sha256=?,sha256=?,encrypted_envelope=?,encrypted_bytes=?,status='pending',postpone_count=0,requarantine_count=requarantine_count+1,expires_at=? WHERE quarantine_id=?""",
            (
                item["created_at"],
                item["updated_at"],
                item["reason"],
                item.get("writer_id"),
                item.get("source"),
                item.get("source_content_sha256"),
                item["sha256"],
                envelope,
                len(envelope.encode("utf-8")),
                item.get("expires_at"),
                quarantine_id,
            ),
        )
        await insert_event(
            tx,
            quarantine_id,
            "content_changed" if content_changed else "safety_reopened",
            item["updated_at"],
            {"kind": item["kind"], "sha256": item["sha256"]},
        )

    async def _assert_capacity(
        self,
        tx: Tx,
        item: dict[str, Any],
        existing: dict[str, Any] | None,
        capacity: Capacity,
        at: str,
    ) -> None:
        totals = (
            await tx.fetchone(
                """SELECT
            COALESCE(SUM(CASE WHEN status IN ('pending','postponed') AND NOT(expires_at IS NOT NULL AND expires_at<=?) THEN 1 ELSE 0 END),0) pending_count,
            COALESCE(SUM(CASE WHEN status IN ('pending','postponed') AND expires_at IS NOT NULL AND expires_at<=? THEN 0 ELSE encrypted_bytes END),0) encrypted_bytes,
            COALESCE(SUM(CASE WHEN kind='security_event' THEN 1 ELSE 0 END),0) security_event_count
            FROM quarantine_items""",
                (at, at),
            )
            or {}
        )
        if (
            item["kind"] == "security_event"
            and existing is None
            and int(totals.get("security_event_count") or 0) >= SECURITY_EVENT_IDENTITY_LIMIT
        ):
            raise HttpError(
                507,
                "quarantine_security_event_capacity_exceeded",
                "security event identity capacity is exhausted",
            )
        existing_live = existing if existing and not _expired(existing, at) else None
        existing_pending = _is_pending(existing_live)
        next_pending = int(totals.get("pending_count") or 0) - int(existing_pending) + 1
        existing_bytes = int(existing_live.get("encrypted_bytes") or 0) if existing_live else 0
        item_bytes = len(
            json.dumps(item["encrypted"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )
        next_bytes = int(totals.get("encrypted_bytes") or 0) - existing_bytes + item_bytes
        if next_pending > capacity.max_pending_items or next_bytes > capacity.max_encrypted_bytes:
            raise HttpError(507, "quarantine_capacity_exceeded", "quarantine capacity is exhausted")
        await self._assert_bank_capacity(tx, item, existing_live, existing_pending, capacity, at)
        if capacity.max_pending_items_per_writer <= 0:
            return
        scoped = await _scoped_pending_count(tx, item, at)
        if existing_pending and existing_live and _same_scope(item, existing_live):
            scoped -= 1
        if scoped + 1 > capacity.max_pending_items_per_writer:
            raise HttpError(
                507,
                "quarantine_writer_capacity_exceeded",
                "writer quarantine capacity is exhausted",
            )

    @staticmethod
    async def _assert_bank_capacity(
        tx: Tx,
        item: dict[str, Any],
        existing_live: dict[str, Any] | None,
        existing_pending: bool,
        capacity: Capacity,
        at: str,
    ) -> None:
        bank_id = item.get("bank_id")
        if capacity.max_pending_items_per_bank <= 0 or bank_id is None:
            return
        row = await tx.fetchone(
            _PENDING_SCOPE_PREFIX + "bank_id=?",
            (at, bank_id),
        )
        bank_pending = int((row or {}).get("count") or 0)
        if existing_pending and existing_live and existing_live.get("bank_id") == bank_id:
            bank_pending -= 1
        if bank_pending + 1 > capacity.max_pending_items_per_bank:
            raise HttpError(
                507,
                "quarantine_bank_capacity_exceeded",
                "bank quarantine capacity is exhausted",
            )


def _is_pending(item: dict[str, Any] | None) -> bool:
    return bool(item and item.get("status") in REVIEWABLE_STATUSES)


async def _scoped_pending_count(tx: Tx, item: dict[str, Any], at: str) -> int:
    if item.get("reason") == "unknown_writer":
        row = await tx.fetchone(_PENDING_SCOPE_PREFIX + "reason='unknown_writer'", (at,))
    elif item.get("writer_id") is not None:
        row = await tx.fetchone(
            _PENDING_SCOPE_PREFIX + "reason <> 'unknown_writer' AND writer_id=?",
            (at, item["writer_id"]),
        )
    else:
        row = await tx.fetchone(
            _PENDING_SCOPE_PREFIX + "reason <> 'unknown_writer' AND writer_id IS NULL AND kind=?",
            (at, item["kind"]),
        )
    return int((row or {}).get("count") or 0)


def _params(item: dict[str, Any], envelope: str) -> tuple[Any, ...]:
    return (
        item["quarantine_id"],
        item["created_at"],
        item["updated_at"],
        item["kind"],
        item["reason"],
        item.get("writer_id"),
        item.get("source"),
        item.get("source_bank"),
        item.get("source_memory_id"),
        item.get("source_content_sha256"),
        item.get("dedupe_key"),
        item["sha256"],
        envelope,
        len(envelope.encode("utf-8")),
        item["status"],
        item["postpone_count"],
        item.get("requarantine_count", 0),
        item.get("expires_at"),
        item.get("bank_id"),
    )


def _summary(item: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "quarantine_id",
        "created_at",
        "updated_at",
        "kind",
        "reason",
        "writer_id",
        "source",
        "source_bank",
        "source_memory_id",
        "dedupe_key",
        "sha256",
        "status",
        "postpone_count",
        "requarantine_count",
        "encrypted_bytes",
        "expires_at",
        "bank_id",
    )
    return {key: item[key] for key in keys if item.get(key) is not None}


def is_expired(item: dict[str, Any], at: str) -> bool:
    expires_at = item.get("expires_at")
    return expires_at is not None and str(expires_at) <= at


def _expired(item: dict[str, Any], at: str) -> bool:
    return item.get("status") in REVIEWABLE_STATUSES and is_expired(item, at)


def _same_scope(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left.get("reason") == "unknown_writer" or right.get("reason") == "unknown_writer":
        return left.get("reason") == right.get("reason") == "unknown_writer"
    if left.get("writer_id") is not None or right.get("writer_id") is not None:
        return left.get("writer_id") is not None and left.get("writer_id") == right.get("writer_id")
    return left.get("kind") == right.get("kind")
