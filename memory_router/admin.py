from __future__ import annotations

import hmac
from datetime import datetime
from typing import Any, cast

from .canonical import sha256_hex
from .envelope import QUARANTINE_ID_RE, canonical_decrypted, parse_decrypted
from .errors import HttpError
from .maintenance import cleanup, preview_cleanup
from .policy import prepare_retain_body
from .review_repository import (
    claim_review,
    finish_approve_memory,
    finish_approve_retain,
    finish_reject_memory,
    interrupt_review,
    postpone,
    remove,
)
from .security import scan_retain_body
from .timestamps import iso_now
from .validation import parse_retain_body


class QuarantineAdminService:
    def __init__(
        self,
        repository: Any,
        hindsight: Any,
        registry: Any,
        limits: Any,
        max_postpones: int = 3,
        review_stale_seconds: int = 60,
    ) -> None:
        self.repository = repository
        self.hindsight = hindsight
        self.registry = registry
        self.limits = limits
        self.max_postpones = max_postpones
        self.review_stale_seconds = review_stale_seconds

    async def list_queue(self, limit: int, offset: int) -> dict[str, Any]:
        at = iso_now()
        items = await self.repository.list_reviewable(limit, offset, at)
        stats = await self.repository.stats(at)
        return {"items": items, "total": stats["pending_items"] + stats["postponed_items"]}

    async def read_item(self, quarantine_id: str) -> dict[str, Any]:
        item = await self._require_reviewable(quarantine_id)
        if item.get("encrypted") is None:
            raise HttpError(
                409, "quarantine_payload_unavailable", "quarantine payload is no longer available"
            )
        record = {key: value for key, value in item.items() if key != "encrypted"}
        return {"record": record, "encrypted": item["encrypted"]}

    async def approve(self, quarantine_id: str, body: dict[str, Any]) -> dict[str, Any]:
        item = await self._require_claim_candidate(quarantine_id)
        decrypted = self._verify_exact(item, body.get("decrypted"))
        if item["kind"] == "retain_request":
            payload = decrypted["payload"]
            if not isinstance(payload, dict) or payload.get("action") != "retain":
                raise HttpError(
                    409, "invalid_quarantine_payload", "retain approval requires a retain request"
                )
            writer_id = payload.get("writer_id")
            if not isinstance(writer_id, str) or not writer_id:
                raise HttpError(400, "invalid_request", "writer_id is required")
            writer = self.registry.writers.get(writer_id)
            if writer is None:
                raise HttpError(
                    409,
                    "writer_not_registered",
                    "register the writer before approving its original retain request",
                )
            retain_body = parse_retain_body(payload.get("body"))
            scan = scan_retain_body(retain_body)
            if not scan.safe and item.get("reason") != "suspicious_content":
                raise HttpError(
                    409,
                    "quarantine_security_review_required",
                    "unsafe retain cannot be approved from an unknown-writer review; resubmit after registering the writer so it is classified as suspicious_content",
                )
            self.limits.assert_retain_bounds(retain_body)
            source = str(item.get("source") or "quarantine_review")
            approved_body = prepare_retain_body(
                retain_body, writer_id, source, writer.write_bank, decision="approved"
            )
            at = iso_now()
            claimed = await claim_review(
                self.repository,
                quarantine_id,
                "retain_request",
                at,
                self.review_stale_seconds,
                expected_sha256=str(item["sha256"]),
                expected_updated_at=_optional_str(item.get("updated_at")),
            )
            try:
                await self.limits.consume_retain(writer_id)
                await self.hindsight.retain(writer.write_bank, approved_body)
                await finish_approve_retain(
                    self.repository,
                    quarantine_id,
                    at,
                    {"writer_id": writer_id, "target_bank": writer.write_bank},
                    expected_sha256=str(item["sha256"]),
                )
            except Exception as exc:
                await interrupt_review(self.repository, claimed, at, exc)
                raise
            return {
                "approved": True,
                "quarantine_id": quarantine_id,
                "target_bank": writer.write_bank,
            }
        if item["kind"] == "recalled_memory":
            payload = decrypted["payload"]
            if (
                not isinstance(payload, dict)
                or payload.get("action") != "recalled_memory"
                or not isinstance(payload.get("result"), dict)
            ):
                raise HttpError(
                    409,
                    "invalid_quarantine_payload",
                    "recalled memory approval requires a recalled memory payload",
                )
            bank_id = payload.get("bank_id")
            result = payload["result"]
            if bank_id != item.get("source_bank") or result.get("id") != item.get(
                "source_memory_id"
            ):
                raise HttpError(
                    409,
                    "quarantine_source_mismatch",
                    "recalled memory source does not match quarantine metadata",
                )
            at = iso_now()
            claimed = await claim_review(
                self.repository,
                quarantine_id,
                "recalled_memory",
                at,
                self.review_stale_seconds,
                expected_sha256=str(item["sha256"]),
                expected_updated_at=_optional_str(item.get("updated_at")),
            )
            try:
                await finish_approve_memory(
                    self.repository,
                    quarantine_id,
                    at,
                    expected_sha256=str(item["sha256"]),
                )
            except Exception as exc:
                await interrupt_review(self.repository, claimed, at, exc)
                raise
            return {
                "reviewed": True,
                "allowed": True,
                "quarantine_id": quarantine_id,
                "source_bank": bank_id,
                "source_memory_id": result["id"],
            }
        raise HttpError(
            409, "invalid_review_action", "this quarantine item cannot be approved into memory"
        )

    async def reject(self, quarantine_id: str) -> dict[str, Any]:
        item = await self._require_claim_candidate(quarantine_id)
        if item["kind"] == "recalled_memory":
            bank_id = item.get("source_bank")
            memory_id = item.get("source_memory_id")
            if not bank_id or not memory_id:
                raise HttpError(
                    409, "quarantine_source_missing", "recalled memory source metadata is missing"
                )
            at = iso_now()
            claimed = await claim_review(
                self.repository,
                quarantine_id,
                "recalled_memory",
                at,
                self.review_stale_seconds,
                expected_sha256=str(item["sha256"]),
                expected_updated_at=_optional_str(item.get("updated_at")),
            )
            try:
                await self.hindsight.invalidate_memory(
                    bank_id,
                    memory_id,
                    f"Rejected by memory-router quarantine review {quarantine_id}",
                )
                await finish_reject_memory(
                    self.repository,
                    quarantine_id,
                    at,
                    expected_sha256=str(item["sha256"]),
                )
            except Exception as exc:
                await interrupt_review(self.repository, claimed, at, exc)
                raise
            return {
                "reviewed": True,
                "allowed": False,
                "quarantine_id": quarantine_id,
                "source_bank": bank_id,
                "source_memory_id": memory_id,
            }
        await remove(
            self.repository,
            quarantine_id,
            "rejected",
            iso_now(),
            self.review_stale_seconds,
        )
        return {"rejected": True, "quarantine_id": quarantine_id}

    async def postpone(self, quarantine_id: str) -> dict[str, Any]:
        await self._require_claim_candidate(quarantine_id)
        next_item = await postpone(
            self.repository,
            quarantine_id,
            iso_now(),
            self.review_stale_seconds,
            self.max_postpones,
        )
        return {
            "postponed": True,
            "quarantine_id": quarantine_id,
            "count": next_item["postpone_count"],
        }

    async def stats(self) -> dict[str, int]:
        stats = await self.repository.stats(iso_now())
        return {
            key: stats[key]
            for key in (
                "total_items",
                "pending_items",
                "postponed_items",
                "reviewed_allowed_items",
                "reviewed_blocked_items",
                "encrypted_bytes",
                "event_count",
            )
        }

    async def cleanup(self, body: dict[str, Any]) -> dict[str, Any]:
        scope = body.get("scope", "pending")
        if scope not in {"pending", "all"}:
            raise HttpError(400, "invalid_request", "scope must be pending or all")
        reasons = body.get("reasons")
        older_than = body.get("older_than")
        if older_than is not None:
            try:
                datetime.fromisoformat(str(older_than).replace("Z", "+00:00"))
            except ValueError as exc:
                raise HttpError(
                    400, "invalid_cleanup_time", "older_than must be an ISO timestamp"
                ) from exc
        preview = await preview_cleanup(self.repository, scope, reasons, older_than)
        if body.get("dry_run") is not False:
            return {"dry_run": True, **preview}
        expected = body.get("expected_count")
        if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
            raise HttpError(
                400, "expected_count_required", "expected_count from a dry run is required"
            )
        result = await cleanup(self.repository, scope, reasons, older_than, expected, iso_now())
        return {"dry_run": False, **result}

    async def _require_reviewable(self, quarantine_id: str) -> dict[str, Any]:
        item = await self._require_item(quarantine_id)
        if item["status"] not in {"pending", "postponed"}:
            raise HttpError(
                409, "quarantine_already_finalized", "quarantine item is not pending review"
            )
        self._assert_not_expired(item)
        return item

    async def _require_claim_candidate(self, quarantine_id: str) -> dict[str, Any]:
        item = await self._require_item(quarantine_id)
        if item["status"] not in {"pending", "postponed", "review_in_progress"}:
            raise HttpError(
                409, "quarantine_already_finalized", "quarantine item is not pending review"
            )
        if item["status"] in {"pending", "postponed"}:
            self._assert_not_expired(item)
        return item

    async def _require_item(self, quarantine_id: str) -> dict[str, Any]:
        if not QUARANTINE_ID_RE.fullmatch(quarantine_id):
            raise HttpError(400, "invalid_quarantine_id", "invalid quarantine_id")
        item = await self.repository.get(quarantine_id)
        if item is None:
            raise HttpError(404, "quarantine_not_found", "quarantine item not found")
        return cast(dict[str, Any], item)

    @staticmethod
    def _assert_not_expired(item: dict[str, Any]) -> None:
        expires_at = item.get("expires_at")
        if expires_at is not None and str(expires_at) <= iso_now():
            raise HttpError(409, "quarantine_expired", "quarantine item has expired")

    @staticmethod
    def _verify_exact(item: dict[str, Any], value: Any) -> dict[str, Any]:
        if item.get("encrypted") is None:
            raise HttpError(
                409, "quarantine_payload_unavailable", "quarantine payload is no longer available"
            )
        try:
            decrypted = parse_decrypted(value)
        except ValueError as exc:
            raise HttpError(400, "invalid_decrypted_quarantine", str(exc)) from exc
        actual = sha256_hex(canonical_decrypted(decrypted))
        if not hmac.compare_digest(actual, str(item["sha256"])):
            raise HttpError(
                409,
                "quarantine_hash_mismatch",
                "decrypted quarantine content differs from the original item",
            )
        for field in ("quarantine_id", "reason", "writer_id", "source"):
            if decrypted.get(field) != item.get(field):
                raise HttpError(
                    409,
                    "quarantine_metadata_mismatch",
                    "decrypted quarantine metadata differs from the stored item",
                )
        return decrypted


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)
