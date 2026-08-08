from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

from memory_router.errors import HttpError
from .db import Database, SqlSession

RETENTION_EVENT_QUARANTINE_ID = "quarantine_retention"
RETENTION_SWEEP_BATCH_LIMIT = 1000
SCHEMA_COLUMNS = (
    ("dedupe_key", "dedupe_key TEXT"),
    ("requarantine_count", "requarantine_count INTEGER NOT NULL DEFAULT 0"),
    ("expires_at", "expires_at TEXT"),
)


@dataclass(slots=True)
class StoredItem:
    quarantine_id: str
    created_at: str
    updated_at: str
    kind: str
    reason: str
    sha256: str
    status: str
    postpone_count: int
    requarantine_count: int = 0
    writer_id: str | None = None
    source: str | None = None
    source_bank: str | None = None
    source_memory_id: str | None = None
    source_content_sha256: str | None = None
    dedupe_key: str | None = None
    expires_at: str | None = None
    encrypted: dict[str, Any] | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "quarantine_id": self.quarantine_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "kind": self.kind,
            "reason": self.reason,
            **({"writer_id": self.writer_id} if self.writer_id is not None else {}),
            **({"source": self.source} if self.source is not None else {}),
            **({"source_bank": self.source_bank} if self.source_bank is not None else {}),
            **({"source_memory_id": self.source_memory_id} if self.source_memory_id is not None else {}),
            **({"dedupe_key": self.dedupe_key} if self.dedupe_key is not None else {}),
            "sha256": self.sha256,
            "status": self.status,
            "postpone_count": self.postpone_count,
            "requarantine_count": self.requarantine_count,
        }


@dataclass(slots=True)
class NewItem:
    quarantine_id: str
    created_at: str
    updated_at: str
    kind: str
    reason: str
    sha256: str
    encrypted: dict[str, Any]
    status: str = "pending"
    postpone_count: int = 0
    requarantine_count: int = 0
    writer_id: str | None = None
    source: str | None = None
    source_bank: str | None = None
    source_memory_id: str | None = None
    source_content_sha256: str | None = None
    dedupe_key: str | None = None
    expires_at: str | None = None


@dataclass(frozen=True, slots=True)
class Capacity:
    max_pending_items: int
    max_pending_items_per_writer: int
    max_encrypted_bytes: int


class QuarantineRepository:
    def __init__(self, database: Database) -> None:
        self.db = database

    async def initialize(self) -> None:
        await self.db.initialize()
        async with self.db.transaction() as tx:
            await tx.acquire_capacity_lock()
            await tx.execute_script(
                """
                CREATE TABLE IF NOT EXISTS quarantine_items (
                  quarantine_id TEXT PRIMARY KEY,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  kind TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  writer_id TEXT,
                  source TEXT,
                  source_bank TEXT,
                  source_memory_id TEXT,
                  source_content_sha256 TEXT,
                  dedupe_key TEXT,
                  sha256 TEXT NOT NULL,
                  encrypted_envelope TEXT,
                  encrypted_bytes INTEGER NOT NULL DEFAULT 0,
                  status TEXT NOT NULL,
                  postpone_count INTEGER NOT NULL DEFAULT 0,
                  requarantine_count INTEGER NOT NULL DEFAULT 0,
                  expires_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_quarantine_items_review
                  ON quarantine_items(status, created_at);
                CREATE INDEX IF NOT EXISTS idx_quarantine_items_reason
                  ON quarantine_items(reason, status, created_at);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_items_source_memory
                  ON quarantine_items(source_bank, source_memory_id)
                  WHERE source_bank IS NOT NULL AND source_memory_id IS NOT NULL;
                CREATE TABLE IF NOT EXISTS quarantine_events (
                  event_id TEXT PRIMARY KEY,
                  quarantine_id TEXT NOT NULL,
                  occurred_at TEXT NOT NULL,
                  event_type TEXT NOT NULL,
                  details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_quarantine_events_item
                  ON quarantine_events(quarantine_id, occurred_at);
                CREATE INDEX IF NOT EXISTS idx_quarantine_events_type
                  ON quarantine_events(event_type, occurred_at);
                """
            )
            for name, definition in SCHEMA_COLUMNS:
                await self._ensure_column(tx, name, definition)
            await tx.execute_script(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_items_dedupe_key
                  ON quarantine_items(dedupe_key) WHERE dedupe_key IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_quarantine_items_expires_at
                  ON quarantine_items(expires_at) WHERE expires_at IS NOT NULL;
                """
            )
        await self.recover_interrupted_reviews(_now_iso())

    async def _ensure_column(self, tx: SqlSession, name: str, definition: str) -> None:
        if tx.dialect == "postgres":
            present = await tx.get(
                """SELECT 1 AS present FROM information_schema.columns
                   WHERE table_schema = current_schema()
                     AND table_name = %s AND column_name = %s""",
                ("quarantine_items", name),
            )
        else:
            present = await tx.get(
                "SELECT 1 AS present FROM pragma_table_info('quarantine_items') WHERE name = ?",
                (name,),
            )
        if present is None:
            await tx.run(f"ALTER TABLE quarantine_items ADD COLUMN {definition}")

    async def ping(self) -> None:
        await self.db.get("SELECT 1 AS ready")

    async def close(self) -> None:
        await self.db.close()

    async def get(self, quarantine_id: str) -> StoredItem | None:
        row = await self.db.get(
            f"SELECT * FROM quarantine_items WHERE quarantine_id = {self.db.placeholder(1)}",
            (quarantine_id,),
        )
        return _parse_item(row) if row else None

    async def find_memory_state(self, bank: str, memory_id: str) -> StoredItem | None:
        p = self.db.placeholder
        row = await self.db.get(
            f"SELECT * FROM quarantine_items WHERE source_bank = {p(1)} AND source_memory_id = {p(2)}",
            (bank, memory_id),
        )
        return _parse_item(row) if row else None

    async def list_reviewable(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        p = self.db.placeholder
        rows = await self.db.all(
            f"""SELECT * FROM quarantine_items
                WHERE status IN ('pending','postponed')
                ORDER BY created_at ASC LIMIT {p(1)} OFFSET {p(2)}""",
            (limit, offset),
        )
        return [_parse_item(row).summary() for row in rows]

    async def stats(self) -> dict[str, int]:
        at = _now_iso()
        p = self.db.placeholder
        row = await self.db.get(
            f"""SELECT
                COUNT(*) AS total_items,
                SUM(CASE WHEN status='pending' AND NOT
                    (expires_at IS NOT NULL AND expires_at <= {p(1)}) THEN 1 ELSE 0 END) AS pending_items,
                SUM(CASE WHEN status='postponed' AND NOT
                    (expires_at IS NOT NULL AND expires_at <= {p(2)}) THEN 1 ELSE 0 END) AS postponed_items,
                SUM(CASE WHEN status IN ('pending','postponed') AND expires_at IS NOT NULL
                    AND expires_at <= {p(3)} THEN 1 ELSE 0 END) AS expired_items,
                SUM(CASE WHEN status='reviewed_allowed' THEN 1 ELSE 0 END) AS reviewed_allowed_items,
                SUM(CASE WHEN status='reviewed_blocked' THEN 1 ELSE 0 END) AS reviewed_blocked_items,
                COALESCE(SUM(CASE WHEN status IN ('pending','postponed')
                    AND expires_at IS NOT NULL AND expires_at <= {p(4)}
                    THEN 0 ELSE encrypted_bytes END),0) AS encrypted_bytes
                FROM quarantine_items""",
            (at, at, at, at),
        )
        events = await self.db.get("SELECT COUNT(*) AS event_count FROM quarantine_events")
        return {
            "total_items": int((row or {}).get("total_items") or 0),
            "pending_items": int((row or {}).get("pending_items") or 0),
            "postponed_items": int((row or {}).get("postponed_items") or 0),
            "expired_items": int((row or {}).get("expired_items") or 0),
            "reviewed_allowed_items": int((row or {}).get("reviewed_allowed_items") or 0),
            "reviewed_blocked_items": int((row or {}).get("reviewed_blocked_items") or 0),
            "encrypted_bytes": int((row or {}).get("encrypted_bytes") or 0),
            "event_count": int((events or {}).get("event_count") or 0),
        }

    async def insert(self, item: NewItem, capacity: Capacity | None = None) -> None:
        await self._store(item, capacity, "id")

    async def upsert_recalled_memory(self, item: NewItem, capacity: Capacity | None = None) -> None:
        if not item.source_bank or not item.source_memory_id:
            raise ValueError("recalled memory source identity is required")
        await self._store(item, capacity, "source")

    async def upsert_security_event(self, item: NewItem, capacity: Capacity | None = None) -> None:
        if item.kind != "security_event":
            raise ValueError("security event item is required")
        await self._store(item, capacity, "id")

    async def upsert_request_item(self, item: NewItem, capacity: Capacity | None = None) -> None:
        if item.kind not in {"retain_request", "recall_request"} or not item.dedupe_key:
            raise ValueError("request item dedupe identity is required")
        await self._store(item, capacity, "dedupe", refresh_only_reviewable=True)

    async def _store(
        self,
        item: NewItem,
        capacity: Capacity | None,
        identity: str,
        refresh_only_reviewable: bool = False,
    ) -> None:
        async with self.db.transaction() as tx:
            await tx.acquire_capacity_lock()
            existing = await self._find_existing(tx, item, identity, True)
            if identity == "id" and existing and item.kind != "security_event":
                raise ValueError("duplicate quarantine_id")
            await self._assert_capacity(tx, item, existing, capacity)
            if existing:
                if not refresh_only_reviewable or existing.status in {"pending", "postponed"}:
                    await self._update_item(tx, existing.quarantine_id, item)
                    await self._event(
                        tx,
                        existing.quarantine_id,
                        "requarantined",
                        item.created_at,
                        {
                            "kind": item.kind,
                            "reason": item.reason,
                            "sha256": item.sha256,
                            "requarantine_count": existing.requarantine_count + 1,
                        },
                    )
            else:
                await self._insert_item(tx, item)
                await self._event(
                    tx,
                    item.quarantine_id,
                    "quarantined",
                    item.created_at,
                    {"kind": item.kind, "reason": item.reason, "sha256": item.sha256},
                )

    async def _find_existing(
        self, tx: SqlSession, item: NewItem, identity: str, lock: bool
    ) -> StoredItem | None:
        lock_clause = tx.row_lock_clause if lock else ""
        if identity == "source":
            p = tx.placeholder
            row = await tx.get(
                f"SELECT * FROM quarantine_items WHERE source_bank={p(1)} AND source_memory_id={p(2)}{lock_clause}",
                (item.source_bank, item.source_memory_id),
            )
        elif identity == "dedupe":
            row = await tx.get(
                f"SELECT * FROM quarantine_items WHERE dedupe_key={tx.placeholder(1)}{lock_clause}",
                (item.dedupe_key,),
            )
        else:
            row = await tx.get(
                f"SELECT * FROM quarantine_items WHERE quarantine_id={tx.placeholder(1)}{lock_clause}",
                (item.quarantine_id,),
            )
        return _parse_item(row) if row else None

    async def _assert_capacity(
        self, tx: SqlSession, item: NewItem, existing: StoredItem | None, limits: Capacity | None
    ) -> None:
        if limits is None:
            return
        at = _now_iso()
        p = tx.placeholder
        row = await tx.get(
            f"""SELECT
                SUM(CASE WHEN status IN ('pending','postponed')
                    AND NOT (expires_at IS NOT NULL AND expires_at <= {p(1)}) THEN 1 ELSE 0 END) AS reviewable,
                COALESCE(SUM(CASE WHEN status IN ('pending','postponed')
                    AND expires_at IS NOT NULL AND expires_at <= {p(2)} THEN 0 ELSE encrypted_bytes END),0)
                    AS encrypted_bytes
                FROM quarantine_items""",
            (at, at),
        )
        existing_live = existing if existing and not _expired(existing, at) else None
        existing_reviewable = int(existing_live is not None and existing_live.status in {"pending", "postponed"})
        next_pending = int((row or {}).get("reviewable") or 0) - existing_reviewable + 1
        next_bytes = int((row or {}).get("encrypted_bytes") or 0) - _encrypted_bytes(existing_live) + _encrypted_bytes(item)
        if next_pending > limits.max_pending_items or next_bytes > limits.max_encrypted_bytes:
            raise HttpError(507, "quarantine_capacity_exceeded", "quarantine capacity is exhausted")
        if limits.max_pending_items_per_writer <= 0:
            return
        scoped = await self._scoped_count(tx, item, at)
        existing_scoped = int(
            existing_reviewable and existing_live is not None and _same_scope(item, existing_live)
        )
        if scoped - existing_scoped + 1 > limits.max_pending_items_per_writer:
            raise HttpError(
                507,
                "quarantine_writer_capacity_exceeded",
                "writer quarantine capacity is exhausted",
            )

    async def _scoped_count(self, tx: SqlSession, item: NewItem, at: str) -> int:
        p = tx.placeholder
        if item.reason == "unknown_writer":
            scope, values = f"reason={p(2)}", (at, "unknown_writer")
        elif item.writer_id is not None:
            scope, values = f"reason <> 'unknown_writer' AND writer_id={p(2)}", (at, item.writer_id)
        else:
            scope, values = (
                f"reason <> 'unknown_writer' AND writer_id IS NULL AND kind={p(2)}",
                (at, item.kind),
            )
        row = await tx.get(
            f"""SELECT COUNT(*) AS count FROM quarantine_items
                WHERE status IN ('pending','postponed')
                  AND NOT (expires_at IS NOT NULL AND expires_at <= {p(1)})
                  AND {scope}""",
            values,
        )
        return int((row or {}).get("count") or 0)

    async def _insert_item(self, tx: SqlSession, item: NewItem) -> None:
        values = _item_values(item)
        await tx.run(
            f"""INSERT INTO quarantine_items (
              quarantine_id,created_at,updated_at,kind,reason,writer_id,source,
              source_bank,source_memory_id,source_content_sha256,dedupe_key,sha256,
              encrypted_envelope,encrypted_bytes,status,postpone_count,requarantine_count,expires_at
            ) VALUES ({','.join(tx.placeholder(i) for i in range(1,19))})""",
            values,
        )

    async def _update_item(self, tx: SqlSession, qid: str, item: NewItem) -> None:
        p = tx.placeholder
        envelope = _envelope_json(item.encrypted)
        await tx.run(
            f"""UPDATE quarantine_items SET
              created_at={p(1)},updated_at={p(2)},kind={p(3)},reason={p(4)},writer_id={p(5)},
              source={p(6)},source_bank={p(7)},source_memory_id={p(8)},source_content_sha256={p(9)},
              dedupe_key={p(10)},sha256={p(11)},encrypted_envelope={p(12)},encrypted_bytes={p(13)},
              expires_at={p(14)},status='pending',postpone_count=0,
              requarantine_count=requarantine_count+1 WHERE quarantine_id={p(15)}""",
            (
                item.created_at, item.updated_at, item.kind, item.reason, item.writer_id, item.source,
                item.source_bank, item.source_memory_id, item.source_content_sha256, item.dedupe_key,
                item.sha256, envelope, len(envelope.encode()), item.expires_at, qid,
            ),
        )

    async def postpone(self, qid: str, at: str) -> StoredItem:
        async with self.db.transaction() as tx:
            current = await self._require_reviewable(tx, qid)
            p = tx.placeholder
            await tx.run(
                f"""UPDATE quarantine_items SET status='postponed',
                    postpone_count=postpone_count+1,updated_at={p(1)} WHERE quarantine_id={p(2)}""",
                (at, qid),
            )
            await self._event(
                tx, qid, "postponed", at, {"postpone_count": current.postpone_count + 1}
            )
            row = await tx.get(f"SELECT * FROM quarantine_items WHERE quarantine_id={p(1)}", (qid,))
            assert row
            return _parse_item(row)

    async def mark_memory_reviewed(self, qid: str, status: str, at: str) -> None:
        async with self.db.transaction() as tx:
            current = await self._require_reviewable(tx, qid)
            if current.kind != "recalled_memory":
                raise HttpError(409, "invalid_review_action", "only recalled memories can be marked reviewed")
            await self._mark_recalled(tx, current, status, at)

    async def approve_retain(
        self, qid: str, at: str, details: dict[str, Any], operation: Callable[[], Awaitable[None]]
    ) -> None:
        claimed = await self._claim(qid, "retain_request", "only retain requests can be approved into Hindsight", at)
        try:
            await operation()
        except BaseException as exc:
            await self._interrupt(claimed, at, exc)
            raise
        async with self.db.transaction() as tx:
            await self._require_in_progress(tx, qid, at)
            await self._delete_with_event(tx, qid, "approved", at, details)

    async def reject_recalled_memory(
        self, qid: str, at: str, operation: Callable[[], Awaitable[None]]
    ) -> None:
        claimed = await self._claim(qid, "recalled_memory", "only recalled memories can be invalidated", at)
        try:
            await operation()
        except BaseException as exc:
            await self._interrupt(claimed, at, exc)
            raise
        async with self.db.transaction() as tx:
            current = await self._require_in_progress(tx, qid, at)
            await self._mark_recalled(tx, current, "reviewed_blocked", at)

    async def remove(self, qid: str, event_type: str, at: str, details: dict[str, Any] | None = None) -> None:
        async with self.db.transaction() as tx:
            await self._require_item(tx, qid)
            await self._delete_with_event(tx, qid, event_type, at, details or {})

    async def _claim(self, qid: str, kind: str, message: str, at: str) -> StoredItem:
        async with self.db.transaction() as tx:
            current = await self._find_id(tx, qid, True)
            if current is None:
                raise HttpError(404, "quarantine_not_found", "quarantine item not found")
            if current.status == "review_in_progress" and _claim_stale(current.updated_at, at):
                current = await self._restore_stale(tx, current, at)
            if current.status not in {"pending", "postponed"}:
                raise HttpError(409, "quarantine_already_finalized", "quarantine item is not pending review")
            if current.kind != kind:
                raise HttpError(409, "invalid_review_action", message)
            p = tx.placeholder
            await tx.run(
                f"UPDATE quarantine_items SET status='review_in_progress',updated_at={p(1)} WHERE quarantine_id={p(2)}",
                (at, qid),
            )
            return current

    async def _interrupt(self, claimed: StoredItem, at: str, error: BaseException) -> None:
        async with self.db.transaction() as tx:
            current = await self._find_id(tx, claimed.quarantine_id, True)
            if not current or current.status != "review_in_progress" or current.updated_at != at:
                return
            p = tx.placeholder
            await tx.run(
                f"UPDATE quarantine_items SET status={p(1)},updated_at={p(2)} WHERE quarantine_id={p(3)}",
                (claimed.status, at, claimed.quarantine_id),
            )
            await self._event(
                tx,
                claimed.quarantine_id,
                "review_interrupted",
                at,
                {"outcome": "restored", "status": claimed.status, "error_kind": _gateway_error_kind(error)},
            )

    async def recover_interrupted_reviews(self, at: str) -> None:
        async with self.db.transaction() as tx:
            rows = await tx.all(
                f"SELECT * FROM quarantine_items WHERE status='review_in_progress'{tx.row_lock_clause}"
            )
            for row in rows:
                item = _parse_item(row)
                if _claim_stale(item.updated_at, at):
                    await self._restore_stale(tx, item, at)

    async def _restore_stale(self, tx: SqlSession, item: StoredItem, at: str) -> StoredItem:
        p = tx.placeholder
        await tx.run(
            f"UPDATE quarantine_items SET status='postponed',updated_at={p(1)} WHERE quarantine_id={p(2)} AND status='review_in_progress'",
            (at, item.quarantine_id),
        )
        await self._event(tx, item.quarantine_id, "review_interrupted", at, {"outcome": "postponed", "recovered": True})
        item.status = "postponed"
        item.updated_at = at
        return item

    async def _require_in_progress(self, tx: SqlSession, qid: str, at: str) -> StoredItem:
        item = await self._require_item(tx, qid)
        if item.status != "review_in_progress" or item.updated_at != at:
            raise HttpError(409, "quarantine_review_changed", "quarantine item changed while review was in progress")
        return item

    async def _mark_recalled(self, tx: SqlSession, current: StoredItem, status: str, at: str) -> None:
        p = tx.placeholder
        await tx.run(
            f"""UPDATE quarantine_items SET status={p(1)},encrypted_envelope=NULL,
                encrypted_bytes=0,updated_at={p(2)} WHERE quarantine_id={p(3)}""",
            (status, at, current.quarantine_id),
        )
        await self._event(
            tx,
            current.quarantine_id,
            "reviewed_allowed" if status == "reviewed_allowed" else "reviewed_blocked",
            at,
            {
                "source_bank": current.source_bank,
                "source_memory_id": current.source_memory_id,
                "source_content_sha256": current.source_content_sha256,
            },
        )

    async def preview_cleanup(self, filter_: dict[str, Any]) -> dict[str, int]:
        where, params = _cleanup_where(self.db, filter_)
        row = await self.db.get(
            f"SELECT COUNT(*) AS count,COALESCE(SUM(encrypted_bytes),0) AS encrypted_bytes FROM quarantine_items {where}",
            params,
        )
        return {"count": int((row or {}).get("count") or 0), "encrypted_bytes": int((row or {}).get("encrypted_bytes") or 0)}

    async def cleanup(self, filter_: dict[str, Any], expected_count: int, at: str) -> dict[str, int]:
        async with self.db.transaction() as tx:
            where, params = _cleanup_where(tx, filter_)
            rows = await tx.all(
                f"SELECT quarantine_id,encrypted_bytes FROM quarantine_items {where}{tx.row_lock_clause}",
                params,
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
                await self._delete_with_event(tx, str(row["quarantine_id"]), "cleanup", at, {"filter": filter_})
            return {"count": len(rows), "encrypted_bytes": total}

    async def sweep_expired_items(self, at: str) -> int:
        async with self.db.transaction() as tx:
            p = tx.placeholder
            rows = await tx.all(
                f"""SELECT quarantine_id,expires_at FROM quarantine_items
                    WHERE status IN ('pending','postponed') AND expires_at IS NOT NULL
                      AND expires_at <= {p(1)} ORDER BY expires_at LIMIT {p(2)}{tx.row_lock_clause}""",
                (at, RETENTION_SWEEP_BATCH_LIMIT),
            )
            for row in rows:
                await self._delete_with_event(
                    tx,
                    str(row["quarantine_id"]),
                    "cleanup",
                    at,
                    {"reason": "expired", "expires_at": str(row["expires_at"])},
                )
            return len(rows)

    async def prune_events_before(self, cutoff: str, at: str) -> int:
        async with self.db.transaction() as tx:
            p = tx.placeholder
            if tx.dialect == "postgres":
                rows = await tx.all(
                    f"""DELETE FROM quarantine_events WHERE event_id IN (
                        SELECT event_id FROM quarantine_events WHERE occurred_at < {p(1)}
                        ORDER BY occurred_at LIMIT {p(2)}) RETURNING event_id""",
                    (cutoff, RETENTION_SWEEP_BATCH_LIMIT),
                )
            else:
                selected = await tx.all(
                    f"SELECT event_id FROM quarantine_events WHERE occurred_at < {p(1)} ORDER BY occurred_at LIMIT {p(2)}",
                    (cutoff, RETENTION_SWEEP_BATCH_LIMIT),
                )
                rows = selected
                for row in selected:
                    await tx.run(f"DELETE FROM quarantine_events WHERE event_id={p(1)}", (row["event_id"],))
            if rows:
                await self._event(
                    tx,
                    RETENTION_EVENT_QUARANTINE_ID,
                    "retention_pruned",
                    at,
                    {"pruned_events": len(rows), "older_than": cutoff},
                )
            return len(rows)

    async def _find_id(self, tx: SqlSession, qid: str, lock: bool = False) -> StoredItem | None:
        row = await tx.get(
            f"SELECT * FROM quarantine_items WHERE quarantine_id={tx.placeholder(1)}"
            f"{tx.row_lock_clause if lock else ''}",
            (qid,),
        )
        return _parse_item(row) if row else None

    async def _require_item(self, tx: SqlSession, qid: str) -> StoredItem:
        item = await self._find_id(tx, qid, True)
        if item is None:
            raise HttpError(404, "quarantine_not_found", "quarantine item not found")
        return item

    async def _require_reviewable(self, tx: SqlSession, qid: str) -> StoredItem:
        item = await self._require_item(tx, qid)
        if item.status not in {"pending", "postponed"}:
            raise HttpError(409, "quarantine_already_finalized", "quarantine item is not pending review")
        return item

    async def _delete_with_event(
        self, tx: SqlSession, qid: str, event_type: str, at: str, details: dict[str, Any]
    ) -> None:
        await tx.run(
            f"DELETE FROM quarantine_items WHERE quarantine_id={tx.placeholder(1)}", (qid,)
        )
        await self._event(tx, qid, event_type, at, details)

    async def _event(
        self, tx: SqlSession, qid: str, event_type: str, at: str, details: dict[str, Any]
    ) -> None:
        p = tx.placeholder
        await tx.run(
            f"""INSERT INTO quarantine_events(event_id,quarantine_id,occurred_at,event_type,details)
                VALUES({p(1)},{p(2)},{p(3)},{p(4)},{p(5)})""",
            (str(uuid.uuid4()), qid, at, event_type, json.dumps(details, separators=(",", ":"))),
        )


def _parse_item(row: dict[str, Any]) -> StoredItem:
    return StoredItem(
        quarantine_id=str(row["quarantine_id"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        kind=str(row["kind"]),
        reason=str(row["reason"]),
        writer_id=None if row.get("writer_id") is None else str(row["writer_id"]),
        source=None if row.get("source") is None else str(row["source"]),
        source_bank=None if row.get("source_bank") is None else str(row["source_bank"]),
        source_memory_id=None if row.get("source_memory_id") is None else str(row["source_memory_id"]),
        source_content_sha256=None if row.get("source_content_sha256") is None else str(row["source_content_sha256"]),
        dedupe_key=None if row.get("dedupe_key") is None else str(row["dedupe_key"]),
        sha256=str(row["sha256"]),
        encrypted=None if row.get("encrypted_envelope") is None else json.loads(str(row["encrypted_envelope"])),
        status=str(row["status"]),
        postpone_count=int(row["postpone_count"]),
        requarantine_count=int(row.get("requarantine_count") or 0),
        expires_at=None if row.get("expires_at") is None else str(row["expires_at"]),
    )


def _envelope_json(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _item_values(item: NewItem) -> tuple[Any, ...]:
    envelope = _envelope_json(item.encrypted)
    return (
        item.quarantine_id, item.created_at, item.updated_at, item.kind, item.reason,
        item.writer_id, item.source, item.source_bank, item.source_memory_id,
        item.source_content_sha256, item.dedupe_key, item.sha256, envelope,
        len(envelope.encode("utf-8")), item.status, item.postpone_count,
        item.requarantine_count, item.expires_at,
    )


def _encrypted_bytes(item: StoredItem | NewItem | None) -> int:
    if item is None or item.encrypted is None:
        return 0
    return len(_envelope_json(item.encrypted).encode("utf-8"))


def _expired(item: StoredItem, at: str) -> bool:
    return item.status in {"pending", "postponed"} and item.expires_at is not None and item.expires_at <= at


def _same_scope(left: NewItem, right: StoredItem) -> bool:
    if left.kind == "security_event" or right.kind == "security_event":
        return False
    if left.reason == "unknown_writer" or right.reason == "unknown_writer":
        return left.reason == "unknown_writer" and right.reason == "unknown_writer"
    if left.writer_id is not None or right.writer_id is not None:
        return left.writer_id is not None and left.writer_id == right.writer_id
    return left.kind == right.kind


def _cleanup_where(db: Database | SqlSession, filter_: dict[str, Any]) -> tuple[str, tuple[Any, ...]]:
    conditions = [
        "status IN ('pending','postponed')"
        if filter_.get("scope", "pending") == "pending"
        else "status <> 'review_in_progress'"
    ]
    params: list[Any] = []
    reasons = filter_.get("reasons") or []
    if reasons:
        placeholders = []
        for reason in reasons:
            params.append(reason)
            placeholders.append(db.placeholder(len(params)))
        conditions.append(f"reason IN ({','.join(placeholders)})")
    if filter_.get("older_than"):
        params.append(filter_["older_than"])
        conditions.append(f"created_at < {db.placeholder(len(params))}")
    return f"WHERE {' AND '.join(conditions)}", tuple(params)



def _gateway_error_kind(error: BaseException) -> str:
    try:
        from ..hindsight import gateway_error_kind

        return gateway_error_kind(error)
    except Exception:
        return "unknown"

def _claim_stale(updated_at: str, at: str) -> bool:
    # Current TS behavior uses a bounded stale claim threshold; one minute is deliberately
    # long enough to avoid stealing an active review and short enough for startup recovery.
    try:
        a = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        b = datetime.fromisoformat(at.replace("Z", "+00:00"))
        return (b - a).total_seconds() >= 60
    except ValueError:
        return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
