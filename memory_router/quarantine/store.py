from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from memory_router.config import QuarantineLimits
from memory_router.errors import HttpError
from memory_router.quarantine.crypto import DecryptedQuarantineObject, canonical_json, create_envelope
from memory_router.quarantine.repository import Capacity, NewItem, QuarantineRepository
from memory_router.rate_limits import Bucket, DistinctIdentity, Rule

GLOBAL_WRITES_BUCKET = "quarantine-writes"
FAMILY_SCOPE_BUCKET = "quarantine-request-family"
REQUARANTINE_OPS_BUCKET = "quarantine-requarantine-ops"
AUTH_AUDIT_WRITES_BUCKET = "quarantine-writes:auth-audit"
AUTH_AUDIT_REQUARANTINE_OPS_BUCKET = "quarantine-requarantine-ops:auth-audit"
UNKNOWN_WRITER_BUCKET = "unknown-writer"
_ORDER_INSENSITIVE = {"document_tags", "tags", "types"}


@dataclass(slots=True)
class QuarantineInput:
    timestamp: str
    kind: str
    reason: str
    payload: Any
    writer_id: str | None = None
    source: str | None = None
    source_bank: str | None = None
    source_memory_id: str | None = None
    source_content_sha256: str | None = None
    dedupe_key: str | None = None


class EncryptedDatabaseQuarantineStore:
    def __init__(
        self,
        public_key: str,
        repository: QuarantineRepository,
        limits: QuarantineLimits,
        rate_limiter: Any,
    ) -> None:
        # Validate before accepting traffic.
        from .crypto import decode_public_key

        decode_public_key(public_key)
        self.public_key = public_key
        self.repository = repository
        self.limits = limits
        self.rate_limiter = rate_limiter
        self.capacity = Capacity(
            limits.max_pending_items,
            _effective_writer_limit(limits),
            limits.max_encrypted_bytes,
        )

    async def put(self, input_: QuarantineInput) -> dict[str, str]:
        qid = self._resolve_id(input_)
        decrypted = DecryptedQuarantineObject(
            quarantine_id=qid,
            created_at=input_.timestamp,
            reason=input_.reason,
            writer_id=input_.writer_id,
            source=input_.source,
            payload=input_.payload,
        )
        encrypted = create_envelope(decrypted, self.public_key)
        envelope_bytes = len(
            json.dumps(encrypted, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )
        if envelope_bytes > self.limits.max_item_bytes:
            raise HttpError(
                413,
                "quarantine_item_too_large",
                "encrypted quarantine item exceeds configured size limit",
            )

        async def operation(session: Any) -> dict[str, str]:
            existing = await self.repository.get(qid)
            self._assert_refresh_allowed(input_, existing.status if existing else None)
            known = await self._known_identity(input_, qid, existing is not None)
            await self._charge(input_, known, session)
            item = self._build_item(input_, qid, encrypted)
            if input_.kind == "recalled_memory":
                await self.repository.upsert_recalled_memory(item, self.capacity)
            elif input_.kind == "security_event":
                await self.repository.upsert_security_event(
                    item,
                    Capacity(
                        self.capacity.max_pending_items,
                        0,
                        self.capacity.max_encrypted_bytes,
                    ),
                )
            elif item.dedupe_key:
                await self.repository.upsert_request_item(item, self.capacity)
            else:
                await self.repository.insert(item, self.capacity)
            return {"quarantine_id": qid, "sha256": encrypted["sha256"]}

        return await self.rate_limiter.with_identity_lock(qid, operation)

    def _build_item(
        self, input_: QuarantineInput, qid: str, encrypted: dict[str, Any]
    ) -> NewItem:
        expires_at = None
        if self.limits.item_ttl_days > 0:
            try:
                created = datetime.fromisoformat(input_.timestamp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise HttpError(
                    400,
                    "invalid_quarantine_timestamp",
                    "quarantine timestamp must be an ISO timestamp",
                ) from exc
            expires_at = (
                created + timedelta(days=self.limits.item_ttl_days)
            ).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return NewItem(
            quarantine_id=qid,
            created_at=input_.timestamp,
            updated_at=input_.timestamp,
            kind=input_.kind,
            reason=input_.reason,
            writer_id=input_.writer_id,
            source=input_.source,
            source_bank=input_.source_bank,
            source_memory_id=input_.source_memory_id,
            source_content_sha256=input_.source_content_sha256,
            dedupe_key=input_.dedupe_key,
            expires_at=expires_at,
            sha256=str(encrypted["sha256"]),
            encrypted=encrypted,
        )

    def _assert_refresh_allowed(self, input_: QuarantineInput, status: str | None) -> None:
        if (
            input_.kind in {"retain_request", "recall_request"}
            and input_.dedupe_key
            and status is not None
            and status not in {"pending", "postponed"}
        ):
            raise HttpError(
                409,
                "quarantine_request_in_review",
                "matching quarantine request is already being reviewed",
            )

    async def _known_identity(
        self, input_: QuarantineInput, qid: str, item_exists: bool
    ) -> bool:
        if input_.dedupe_key and input_.kind in {
            "security_event",
            "retain_request",
            "recall_request",
        }:
            return item_exists
        if (
            input_.kind == "recalled_memory"
            and input_.source_bank is not None
            and input_.source_memory_id is not None
        ):
            return (
                await self.repository.find_memory_state(
                    input_.source_bank, input_.source_memory_id
                )
            ) is not None
        return False

    async def _charge(self, input_: QuarantineInput, known: bool, session: Any) -> None:
        window = self.limits.rate_limit_window_ms
        auth_audit = input_.reason == "auth_failed"
        if known:
            await session.consume(
                AUTH_AUDIT_REQUARANTINE_OPS_BUCKET
                if auth_audit
                else REQUARANTINE_OPS_BUCKET,
                Rule(self.limits.requarantine_ops_max, window),
            )
            return
        if self.limits.rate_limit_max <= 0 or await self._capacity_exhausted():
            return
        if auth_audit:
            await session.consume(
                AUTH_AUDIT_WRITES_BUCKET,
                Rule(self.limits.rate_limit_global_max, window),
            )
            return
        writer = (
            UNKNOWN_WRITER_BUCKET
            if input_.reason == "unknown_writer"
            else (input_.writer_id or UNKNOWN_WRITER_BUCKET)
        )
        family = request_family_identity(input_)
        identities = ()
        if family is not None:
            identities = (
                DistinctIdentity(
                    f"{FAMILY_SCOPE_BUCKET}:{family[0]}",
                    family[1],
                    Rule(self.limits.distinct_family_limit_max, window),
                ),
            )
        await session.consume_many_distinct(
            (
                Bucket(
                    f"{GLOBAL_WRITES_BUCKET}:writer:{writer}",
                    Rule(self.limits.rate_limit_max, window),
                ),
                Bucket(
                    GLOBAL_WRITES_BUCKET,
                    Rule(self.limits.rate_limit_global_max, window),
                ),
            ),
            identities,
        )

    async def _capacity_exhausted(self) -> bool:
        stats = await self.repository.stats()
        return (
            stats["pending_items"] + stats["postponed_items"]
            >= self.capacity.max_pending_items
            or stats["encrypted_bytes"] >= self.capacity.max_encrypted_bytes
        )

    def _resolve_id(self, input_: QuarantineInput) -> str:
        if input_.kind == "security_event" and input_.dedupe_key:
            digest = _sha(input_.dedupe_key)
            return f"q_security{digest[:48]}_{digest[48:]}"
        if input_.kind in {"retain_request", "recall_request"} and input_.dedupe_key:
            digest = _sha(input_.dedupe_key)
            return f"q_request{digest[:48]}_{digest[48:]}"
        if (
            input_.kind == "recalled_memory"
            and input_.source_bank is not None
            and input_.source_memory_id is not None
        ):
            digest = _sha(f"{input_.source_bank}:{input_.source_memory_id}")
            return f"q_memory{digest[:48]}_{digest[48:]}"
        cleaned = re.sub(r"[^0-9A-Za-z]", "", input_.timestamp)
        return f"q_{cleaned}_{os.urandom(8).hex()}"


def request_family_identity(input_: QuarantineInput) -> tuple[str, str] | None:
    if input_.kind not in {"retain_request", "recall_request"}:
        return None
    scope_identity = (
        "unknown-writer"
        if input_.reason == "unknown_writer"
        else (input_.writer_id or "anonymous")
    )
    base = {"kind": input_.kind, "reason": input_.reason}
    normalized = _sha(canonical_json({**base, "payload": _normalize(input_.payload)}))
    structural = _sha(canonical_json({**base, "payload": _shape(input_.payload)}))
    return (
        f"{input_.kind}:{input_.reason}:{scope_identity}",
        _sha(f"{normalized}:{structural}"),
    )


def _normalize(value: Any, key: str | None = None) -> Any:
    if isinstance(value, str):
        return " ".join(unicodedata.normalize("NFKC", value).strip().lower().split())
    if isinstance(value, list):
        result = [_normalize(item) for item in value]
        if key in _ORDER_INSENSITIVE:
            return sorted(result, key=lambda item: canonical_json(item))
        return result
    if isinstance(value, dict):
        return {entry_key: _normalize(entry, entry_key) for entry_key, entry in value.items()}
    return value


def _shape(value: Any, key: str | None = None) -> Any:
    if isinstance(value, str):
        normalized = " ".join(unicodedata.normalize("NFKC", value).strip().lower().split())
        return {
            "text_length_bucket": len(normalized) // 32,
            "token_count_bucket": (0 if normalized == "" else len(normalized.split())) // 4,
        }
    if isinstance(value, list):
        result = [_shape(item) for item in value]
        if key in _ORDER_INSENSITIVE:
            return sorted(result, key=lambda item: canonical_json(item))
        return result
    if isinstance(value, dict):
        return {entry_key: _shape(entry, entry_key) for entry_key, entry in value.items()}
    if value is None:
        return "object"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return type(value).__name__


def _sha(value: str | bytes) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def _effective_writer_limit(limits: QuarantineLimits) -> int:
    if limits.max_pending_items_per_writer <= 0:
        return 0
    item_reserve = max(0, limits.max_pending_items - 1)
    byte_reserve = max(0, (limits.max_encrypted_bytes - 1) // limits.max_item_bytes)
    return min(limits.max_pending_items_per_writer, item_reserve, byte_reserve)
