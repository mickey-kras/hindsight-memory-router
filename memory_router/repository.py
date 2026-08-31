from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from .db import Database, Tx
from .errors import HttpError

_MEMORY_SELECT = "SELECT * FROM quarantine_items WHERE source_bank=? AND source_memory_id=?"
_MEMORY_SELECT_FOR_UPDATE = _MEMORY_SELECT + " FOR UPDATE"
_REQUEST_SELECT = "SELECT * FROM quarantine_items WHERE dedupe_key=?"
_REQUEST_SELECT_FOR_UPDATE = _REQUEST_SELECT + " FOR UPDATE"
_ID_SELECT = "SELECT * FROM quarantine_items WHERE quarantine_id=?"
_ID_SELECT_FOR_UPDATE = _ID_SELECT + " FOR UPDATE"
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
    tx: Tx, quarantine_id: str, event_type: str, at: str, details: dict[str, Any] | None = None
) -> None:
    await tx.execute(
        "INSERT INTO quarantine_events(event_id,quarantine_id,occurred_at,event_type,details) VALUES(?,?,?,?,?)",
        (
            str(uuid.uuid4()),
            quarantine_id,
            at,
            event_type,
            json.dumps(details or {}, separators=(",", ":")),
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

    async def list_reviewable(self, limit: int, offset: int, at: str) -> list[dict[str, Any]]:
        async with self.db.transaction() as tx:
            rows = await tx.fetchall(
                "SELECT * FROM quarantine_items WHERE status IN ('pending','postponed') "
                "AND NOT(expires_at IS NOT NULL AND expires_at<=?) "
                "ORDER BY created_at ASC, quarantine_id ASC LIMIT ? OFFSET ?",
                (at, limit, offset),
            )
        return [_summary(stored(row) or {}) for row in rows]

    async def stats(self, at: str) -> dict[str, int]:
        async with self.db.transaction() as tx:
            row = (
                await tx.fetchone(
                    """SELECT COUNT(*) total_items,
              SUM(CASE WHEN status='pending' AND NOT(expires_at IS NOT NULL AND expires_at<=?) THEN 1 ELSE 0 END) pending_items,
              SUM(CASE WHEN status='postponed' AND NOT(expires_at IS NOT NULL AND expires_at<=?) THEN 1 ELSE 0 END) postponed_items,
              SUM(CASE WHEN status IN ('pending','postponed') AND expires_at IS NOT NULL AND expires_at<=? THEN 1 ELSE 0 END) expired_items,
              SUM(CASE WHEN status='reviewed_allowed' THEN 1 ELSE 0 END) reviewed_allowed_items,
              SUM(CASE WHEN status='reviewed_blocked' THEN 1 ELSE 0 END) reviewed_blocked_items,
              COALESCE(SUM(CASE WHEN status IN ('pending','postponed') AND expires_at IS NOT NULL AND expires_at<=? THEN 0 ELSE encrypted_bytes END),0) encrypted_bytes FROM quarantine_items""",
                    (at, at, at, at),
                )
                or {}
            )
            events = await tx.fetchone("SELECT COUNT(*) event_count FROM quarantine_events") or {}
        keys = (
            "total_items",
            "pending_items",
            "postponed_items",
            "expired_items",
            "reviewed_allowed_items",
            "reviewed_blocked_items",
            "encrypted_bytes",
        )
        return {key: int(row.get(key) or 0) for key in keys} | {
            "event_count": int(events.get("event_count") or 0)
        }

    async def store(self, item: dict[str, Any], capacity: Capacity, *, mode: str, at: str) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            existing = await self._find_existing(tx, item, mode)
            if existing and existing["status"] in {
                "review_in_progress",
                "review_side_effect_started",
                "review_side_effect_completed",
            }:
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
                if mode == "request" and existing["status"] not in {"pending", "postponed"}:
                    return
                if mode == "memory" and existing["status"] == "reviewed_allowed":
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
                await self._insert(tx, item)

    async def _find_existing(
        self, tx: Tx, item: dict[str, Any], mode: str
    ) -> dict[str, Any] | None:
        locked = tx.dialect == "postgres"
        if mode == "memory":
            query = _MEMORY_SELECT_FOR_UPDATE if locked else _MEMORY_SELECT
            row = await tx.fetchone(query, (item["source_bank"], item["source_memory_id"]))
        elif mode == "request":
            query = _REQUEST_SELECT_FOR_UPDATE if locked else _REQUEST_SELECT
            row = await tx.fetchone(query, (item["dedupe_key"],))
        else:
            query = _ID_SELECT_FOR_UPDATE if locked else _ID_SELECT
            row = await tx.fetchone(query, (item["quarantine_id"],))
        return stored(row)

    async def _insert(self, tx: Tx, item: dict[str, Any]) -> None:
        envelope = json.dumps(item["encrypted"], separators=(",", ":"), ensure_ascii=False)
        await tx.execute(
            """INSERT INTO quarantine_items(quarantine_id,created_at,updated_at,kind,reason,writer_id,source,source_bank,source_memory_id,source_content_sha256,dedupe_key,sha256,encrypted_envelope,encrypted_bytes,status,postpone_count,requarantine_count,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
            """UPDATE quarantine_items SET updated_at=?,kind=?,reason=?,writer_id=?,source=?,source_bank=?,source_memory_id=?,source_content_sha256=?,dedupe_key=?,sha256=?,encrypted_envelope=?,encrypted_bytes=?,requarantine_count=requarantine_count+1 WHERE quarantine_id=?""",
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
            """UPDATE quarantine_items SET created_at=?,updated_at=?,kind=?,reason=?,writer_id=?,source=?,source_bank=?,source_memory_id=?,source_content_sha256=?,dedupe_key=?,sha256=?,encrypted_envelope=?,encrypted_bytes=?,status='pending',postpone_count=0,requarantine_count=requarantine_count+1,expires_at=? WHERE quarantine_id=?""",
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
            COALESCE(SUM(CASE WHEN status IN ('pending','postponed') AND expires_at IS NOT NULL AND expires_at<=? THEN 0 ELSE encrypted_bytes END),0) encrypted_bytes
            FROM quarantine_items""",
                (at, at),
            )
            or {}
        )
        existing_live = existing if existing and not _expired(existing, at) else None
        existing_pending = bool(
            existing_live and existing_live.get("status") in {"pending", "postponed"}
        )
        next_pending = int(totals.get("pending_count") or 0) - int(existing_pending) + 1
        existing_bytes = int(existing_live.get("encrypted_bytes") or 0) if existing_live else 0
        item_bytes = len(
            json.dumps(item["encrypted"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )
        next_bytes = int(totals.get("encrypted_bytes") or 0) - existing_bytes + item_bytes
        if next_pending > capacity.max_pending_items or next_bytes > capacity.max_encrypted_bytes:
            raise HttpError(507, "quarantine_capacity_exceeded", "quarantine capacity is exhausted")
        if capacity.max_pending_items_per_writer > 0:
            scoped = await _scoped_pending_count(tx, item, at)
            if existing_pending and existing_live and _same_scope(item, existing_live):
                scoped -= 1
            if scoped + 1 > capacity.max_pending_items_per_writer:
                raise HttpError(
                    507,
                    "quarantine_writer_capacity_exceeded",
                    "writer quarantine capacity is exhausted",
                )


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
    )
    return {key: item[key] for key in keys if item.get(key) is not None}


def _expired(item: dict[str, Any], at: str) -> bool:
    return (
        item.get("status") in {"pending", "postponed"}
        and item.get("expires_at") is not None
        and item["expires_at"] <= at
    )


def _same_scope(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left.get("kind") == "security_event" or right.get("kind") == "security_event":
        return False
    if left.get("reason") == "unknown_writer" or right.get("reason") == "unknown_writer":
        return left.get("reason") == right.get("reason") == "unknown_writer"
    if left.get("writer_id") is not None or right.get("writer_id") is not None:
        return left.get("writer_id") is not None and left.get("writer_id") == right.get("writer_id")
    return left.get("kind") == right.get("kind")
