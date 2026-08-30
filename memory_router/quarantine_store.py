from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from .canonical import sha256_hex
from .dedupe import request_family_identity
from .envelope import create_envelope, decode_public_key, estimate_envelope_size
from .errors import HttpError
from .repository import Capacity, QuarantineRepository


@dataclass(frozen=True, slots=True)
class QuarantineLimits:
    max_item_bytes: int = 1_048_576
    max_pending_items: int = 1_000
    max_pending_items_per_writer: int = 50
    max_encrypted_bytes: int = 104_857_600
    rate_limit_max: int = 30
    rate_limit_window_ms: int = 60_000
    rate_limit_global_max: int = 300
    distinct_family_limit_max: int = 10
    requarantine_ops_max: int = 1_000
    item_ttl_days: int = 0


class QuarantineStore:
    def __init__(
        self,
        public_key: str,
        repository: QuarantineRepository,
        limits: QuarantineLimits,
        rate_limiter: Any,
    ) -> None:
        key = decode_public_key(public_key)
        self.public_key = public_key
        self.public_key_bytes = key.key_size // 8
        self.repository = repository
        self.limits = limits
        self.rate_limiter = rate_limiter
        self.capacity = Capacity(
            limits.max_pending_items, _effective_writer_limit(limits), limits.max_encrypted_bytes
        )

    async def put(self, input_: dict[str, Any]) -> dict[str, str]:
        quarantine_id = self._resolve_id(input_)
        self._assert_item_size(input_, quarantine_id)
        existing_for_charge = await self.repository.get(quarantine_id)
        known = await self._known_identity(input_, existing_for_charge is not None)
        await self._charge(input_, known, self.rate_limiter)

        async def operation(_session: Any) -> dict[str, str]:
            existing = await self.repository.get(quarantine_id)
            if (
                input_["kind"] in {"retain_request", "recall_request"}
                and input_.get("dedupeKey")
                and existing
                and existing["status"] not in {"pending", "postponed"}
            ):
                raise HttpError(
                    409,
                    "quarantine_request_in_review",
                    "matching quarantine request is already being reviewed",
                )
            if existing and existing["status"] == "review_in_progress":
                raise HttpError(
                    409,
                    "quarantine_item_in_review",
                    "matching quarantine item is already being reviewed",
                )

            encrypted = self._encrypt(input_, quarantine_id)
            item = self._build_item(input_, quarantine_id, encrypted)
            mode = (
                "memory"
                if input_["kind"] == "recalled_memory"
                else "request"
                if input_["kind"] in {"retain_request", "recall_request"} and item.get("dedupe_key")
                else "id"
            )
            capacity = self.capacity
            if input_["kind"] == "security_event":
                capacity = Capacity(capacity.max_pending_items, 0, capacity.max_encrypted_bytes)
            await self.repository.store(item, capacity, mode=mode, at=input_["timestamp"])
            return {"quarantine_id": quarantine_id, "sha256": str(encrypted["sha256"])}

        return cast(
            dict[str, str], await self.rate_limiter.with_identity_lock(quarantine_id, operation)
        )

    def _decrypted(self, input_: dict[str, Any], quarantine_id: str) -> dict[str, Any]:
        decrypted: dict[str, Any] = {
            "quarantine_id": quarantine_id,
            "created_at": input_["timestamp"],
            "reason": input_["reason"],
            "payload": input_["payload"],
        }
        if input_.get("writerId") is not None:
            decrypted["writer_id"] = input_["writerId"]
        if input_.get("source") is not None:
            decrypted["source"] = input_["source"]
        return decrypted

    def _assert_item_size(self, input_: dict[str, Any], quarantine_id: str) -> None:
        decrypted = self._decrypted(input_, quarantine_id)
        encrypted_bytes = estimate_envelope_size(decrypted, self.public_key_bytes)
        if encrypted_bytes > self.limits.max_item_bytes:
            raise HttpError(
                413,
                "quarantine_item_too_large",
                "encrypted quarantine item exceeds configured size limit",
            )

    def _encrypt(self, input_: dict[str, Any], quarantine_id: str) -> dict[str, Any]:
        return create_envelope(self._decrypted(input_, quarantine_id), self.public_key)

    def _build_item(
        self, input_: dict[str, Any], quarantine_id: str, encrypted: dict[str, Any]
    ) -> dict[str, Any]:
        item: dict[str, Any] = {
            "quarantine_id": quarantine_id,
            "created_at": input_["timestamp"],
            "updated_at": input_["timestamp"],
            "kind": input_["kind"],
            "reason": input_["reason"],
            "writer_id": input_.get("writerId"),
            "source": input_.get("source"),
            "source_bank": input_.get("sourceBank"),
            "source_memory_id": input_.get("sourceMemoryId"),
            "source_content_sha256": input_.get("sourceContentSha256"),
            "dedupe_key": input_.get("dedupeKey"),
            "sha256": encrypted["sha256"],
            "encrypted": encrypted,
            "status": "pending",
            "postpone_count": 0,
            "requarantine_count": 0,
        }
        if self.limits.item_ttl_days > 0:
            try:
                created = datetime.fromisoformat(input_["timestamp"].replace("Z", "+00:00"))
            except ValueError as exc:
                raise HttpError(
                    400,
                    "invalid_quarantine_timestamp",
                    "quarantine timestamp must be an ISO timestamp",
                ) from exc
            item["expires_at"] = (
                (created + timedelta(days=self.limits.item_ttl_days))
                .astimezone(UTC)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
        return item

    async def _known_identity(self, input_: dict[str, Any], item_exists: bool) -> bool:
        if input_.get("dedupeKey") and input_["kind"] in {
            "security_event",
            "retain_request",
            "recall_request",
        }:
            return item_exists
        if (
            input_["kind"] == "recalled_memory"
            and input_.get("sourceBank") is not None
            and input_.get("sourceMemoryId") is not None
        ):
            return (
                await self.repository.find_memory_state(
                    input_["sourceBank"], input_["sourceMemoryId"]
                )
                is not None
            )
        return False

    async def _charge(self, input_: dict[str, Any], known: bool, session: Any) -> None:
        window = self.limits.rate_limit_window_ms
        auth_audit = input_["reason"] == "auth_failed"
        if known:
            key = (
                "quarantine-requarantine-ops:auth-audit"
                if auth_audit
                else "quarantine-requarantine-ops"
            )
            await session.consume_many([(key, self.limits.requarantine_ops_max, window)])
            return
        if self.limits.rate_limit_max <= 0:
            return
        if auth_audit:
            await session.consume_many(
                [("quarantine-writes:auth-audit", self.limits.rate_limit_global_max, window)]
            )
            return
        writer = (
            "unknown-writer"
            if input_["reason"] == "unknown_writer"
            else input_.get("writerId") or "unknown-writer"
        )
        family = request_family_identity(
            input_["kind"], input_["reason"], input_.get("writerId"), input_["payload"]
        )
        identities: list[tuple[str, str, int, int]] = []
        if family:
            identities.append(
                (
                    f"quarantine-request-family:{family[0]}",
                    family[1],
                    self.limits.distinct_family_limit_max,
                    window,
                )
            )
        await session.consume_many_distinct(
            [
                (f"quarantine-writes:writer:{writer}", self.limits.rate_limit_max, window),
                ("quarantine-writes", self.limits.rate_limit_global_max, window),
            ],
            identities,
        )

    def _resolve_id(self, input_: dict[str, Any]) -> str:
        if input_["kind"] == "security_event" and input_.get("dedupeKey"):
            digest = sha256_hex(input_["dedupeKey"])
            return f"q_security{digest[:48]}_{digest[48:]}"
        if input_["kind"] in {"retain_request", "recall_request"} and input_.get("dedupeKey"):
            digest = sha256_hex(input_["dedupeKey"])
            return f"q_request{digest[:48]}_{digest[48:]}"
        if (
            input_["kind"] == "recalled_memory"
            and input_.get("sourceBank") is not None
            and input_.get("sourceMemoryId") is not None
        ):
            digest = sha256_hex(f"{input_['sourceBank']}:{input_['sourceMemoryId']}")
            return f"q_memory{digest[:48]}_{digest[48:]}"
        stamp = re.sub(r"[^0-9A-Za-z]", "", input_["timestamp"])
        return f"q_{stamp}_{secrets.token_hex(8)}"


def _effective_writer_limit(limits: QuarantineLimits) -> int:
    if limits.max_pending_items_per_writer <= 0:
        return 0
    return min(
        limits.max_pending_items_per_writer,
        max(0, limits.max_pending_items - 1),
        max(0, (limits.max_encrypted_bytes - 1) // limits.max_item_bytes),
    )
