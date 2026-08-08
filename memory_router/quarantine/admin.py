from __future__ import annotations

import hmac
import re
from datetime import datetime, timezone
from typing import Any

from memory_router.errors import HttpError
from memory_router.models import BANK_IDS, RecallResult, WriterRegistry
from memory_router.validation import parse_retain_body

from .crypto import canonicalize_decrypted, parse_decrypted, sha256_hex
from .repository import QuarantineRepository, StoredItem

_QID = re.compile(r"^q_[0-9A-Za-z]+_[0-9a-f]{16}$")


class QuarantineAdminService:
    def __init__(
        self,
        repository: QuarantineRepository,
        hindsight: Any,
        registry: WriterRegistry,
        max_postpones: int = 3,
    ) -> None:
        self.repository = repository
        self.hindsight = hindsight
        self.registry = registry
        self.max_postpones = max_postpones

    async def list_queue(self, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        items = await self.repository.list_reviewable(limit, offset)
        stats = await self.repository.stats()
        return {"items": items, "total": stats["pending_items"] + stats["postponed_items"]}

    async def read_item(self, qid: str) -> dict[str, Any]:
        item = await self._require_reviewable(qid)
        if item.encrypted is None:
            raise HttpError(
                409,
                "quarantine_payload_unavailable",
                "quarantine payload is no longer available",
            )
        record = item.summary()
        record.update(
            {
                **({"source_content_sha256": item.source_content_sha256} if item.source_content_sha256 else {}),
                **({"expires_at": item.expires_at} if item.expires_at else {}),
            }
        )
        return {"record": record, "encrypted": item.encrypted}

    async def approve(self, qid: str, body: dict[str, Any]) -> dict[str, Any]:
        item = await self._require_reviewable(qid)
        decrypted = self._verify_exact(item, body.get("decrypted"))
        if item.kind == "retain_request":
            payload = _require_object(decrypted.payload, "quarantine payload")
            if payload.get("action") != "retain":
                raise HttpError(
                    409,
                    "invalid_quarantine_payload",
                    "retain approval requires a retain request",
                )
            writer_id = _require_string(payload.get("writer_id"), "writer_id")
            writer = self.registry.writers.get(writer_id)
            if writer is None:
                raise HttpError(
                    409,
                    "writer_not_registered",
                    "register the writer before approving its original retain request",
                )
            retain_body = parse_retain_body(payload.get("body"))

            async def operation() -> None:
                await self.hindsight.retain(writer.write_bank, retain_body)

            await self.repository.approve_retain(
                qid,
                _now_iso(),
                {"writer_id": writer_id, "target_bank": writer.write_bank},
                operation,
            )
            return {
                "approved": True,
                "quarantine_id": qid,
                "target_bank": writer.write_bank,
            }
        if item.kind == "recalled_memory":
            payload = _require_object(decrypted.payload, "recalled memory payload")
            if payload.get("action") != "recalled_memory":
                raise HttpError(
                    409,
                    "invalid_quarantine_payload",
                    "recalled memory approval requires a recalled memory payload",
                )
            bank = _require_string(payload.get("bank_id"), "bank_id")
            if bank not in BANK_IDS:
                raise HttpError(400, "invalid_request", "bank_id is invalid")
            result = _require_object(payload.get("result"), "recalled result")
            memory_id = _require_string(result.get("id"), "memory id")
            _require_string(result.get("text"), "memory text")
            if bank != item.source_bank or memory_id != item.source_memory_id:
                raise HttpError(
                    409,
                    "quarantine_source_mismatch",
                    "recalled memory source does not match quarantine metadata",
                )
            await self.repository.mark_memory_reviewed(qid, "reviewed_allowed", _now_iso())
            return {
                "reviewed": True,
                "allowed": True,
                "quarantine_id": qid,
                "source_bank": bank,
                "source_memory_id": memory_id,
            }
        raise HttpError(
            409,
            "invalid_review_action",
            "this quarantine item cannot be approved into memory",
        )

    async def reject(self, qid: str) -> dict[str, Any]:
        item = await self._require_reviewable(qid)
        if item.kind == "recalled_memory":
            if not item.source_bank or not item.source_memory_id:
                raise HttpError(
                    409,
                    "quarantine_source_missing",
                    "recalled memory source metadata is missing",
                )

            async def operation() -> None:
                await self.hindsight.invalidate_memory(
                    item.source_bank,
                    item.source_memory_id,
                    f"Rejected by memory-router quarantine review {qid}",
                )

            await self.repository.reject_recalled_memory(qid, _now_iso(), operation)
            return {
                "reviewed": True,
                "allowed": False,
                "quarantine_id": qid,
                "source_bank": item.source_bank,
                "source_memory_id": item.source_memory_id,
            }
        await self.repository.remove(qid, "rejected", _now_iso())
        return {"rejected": True, "quarantine_id": qid}

    async def postpone(self, qid: str) -> dict[str, Any]:
        item = await self._require_reviewable(qid)
        if item.postpone_count >= self.max_postpones:
            raise HttpError(
                409,
                "postpone_limit_reached",
                "maximum postpone count reached; approve, reject, or wait for "
                "QUARANTINE_ITEM_TTL_DAYS expiry",
            )
        next_item = await self.repository.postpone(qid, _now_iso())
        return {
            "postponed": True,
            "quarantine_id": qid,
            "count": next_item.postpone_count,
        }

    async def stats(self) -> dict[str, int]:
        stats = await self.repository.stats()
        return {
            "total_items": stats["total_items"],
            "pending_items": stats["pending_items"],
            "postponed_items": stats["postponed_items"],
            "reviewed_allowed_items": stats["reviewed_allowed_items"],
            "reviewed_blocked_items": stats["reviewed_blocked_items"],
            "encrypted_bytes": stats["encrypted_bytes"],
            "event_count": stats["event_count"],
        }

    async def cleanup(self, body: dict[str, Any]) -> dict[str, Any]:
        filter_ = _cleanup_filter(body)
        preview = await self.repository.preview_cleanup(filter_)
        if body.get("dry_run") is not False:
            return {"dry_run": True, **preview}
        expected = body.get("expected_count")
        if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0:
            raise HttpError(
                400,
                "expected_count_required",
                "expected_count from a dry run is required",
            )
        result = await self.repository.cleanup(filter_, expected, _now_iso())
        return {"dry_run": False, **result}

    def _verify_exact(self, item: StoredItem, value: Any):
        if item.encrypted is None:
            raise HttpError(
                409,
                "quarantine_payload_unavailable",
                "quarantine payload is no longer available",
            )
        try:
            decrypted = parse_decrypted(value)
        except ValueError as exc:
            raise HttpError(400, "invalid_decrypted_quarantine", str(exc)) from exc
        actual = sha256_hex(canonicalize_decrypted(decrypted.to_dict()))
        if not (
            len(actual) == 64
            and len(item.sha256) == 64
            and hmac.compare_digest(actual, item.sha256)
        ):
            raise HttpError(
                409,
                "quarantine_hash_mismatch",
                "decrypted quarantine content differs from the original item",
            )
        if (
            decrypted.quarantine_id != item.quarantine_id
            or decrypted.created_at != item.created_at
            or decrypted.reason != item.reason
            or decrypted.writer_id != item.writer_id
            or decrypted.source != item.source
        ):
            raise HttpError(
                409,
                "quarantine_metadata_mismatch",
                "decrypted quarantine metadata differs from the stored item",
            )
        return decrypted

    async def _require_reviewable(self, qid: str) -> StoredItem:
        if not _QID.fullmatch(qid):
            raise HttpError(400, "invalid_quarantine_id", "invalid quarantine_id")
        item = await self.repository.get(qid)
        if item is None:
            raise HttpError(404, "quarantine_not_found", "quarantine item not found")
        if item.status not in {"pending", "postponed"}:
            raise HttpError(
                409,
                "quarantine_already_finalized",
                "quarantine item is not pending review",
            )
        return item


def _cleanup_filter(body: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise HttpError(400, "invalid_request", "cleanup body must be an object")
    scope = body.get("scope", "pending")
    if scope not in {"pending", "all"}:
        raise HttpError(400, "invalid_request", "cleanup scope is invalid")
    reasons = body.get("reasons")
    if reasons is not None and (
        not isinstance(reasons, list) or any(not isinstance(reason, str) for reason in reasons)
    ):
        raise HttpError(400, "invalid_request", "cleanup reasons are invalid")
    older = body.get("older_than")
    if older:
        try:
            datetime.fromisoformat(str(older).replace("Z", "+00:00"))
        except ValueError as exc:
            raise HttpError(
                400, "invalid_cleanup_time", "older_than must be an ISO timestamp"
            ) from exc
    return {
        "scope": scope,
        **({"reasons": reasons} if reasons else {}),
        **({"older_than": older} if older else {}),
    }


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HttpError(400, "invalid_request", f"{label} must be an object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise HttpError(400, "invalid_request", f"{label} is required")
    return value


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
