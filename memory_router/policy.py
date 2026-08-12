from __future__ import annotations

import asyncio
import logging
from typing import Any, cast

from .canonical import canonical_json, sha256_hex
from .dedupe import SecurityEventIdentityCap, request_dedupe_key, security_event_dedupe_key
from .errors import HttpError
from .hindsight import HindsightGatewayError
from .observability import current_request_id
from .security import SafetyResult, scan_recall_body, scan_recall_result, scan_retain_body
from .timestamps import iso_now

logger = logging.getLogger(__name__)
_RECALL_RESPONSE_MAP_FIELDS = ("chunks", "entities", "source_facts", "trace")


def prepare_retain_body(
    body: dict[str, Any], writer_id: str, source: str, target_bank: str, decision: str = "allowed"
) -> dict[str, Any]:
    rewritten = dict(body)
    rewritten["items"] = []
    for item in body["items"]:
        copied = dict(item)
        metadata = dict(copied.get("metadata") or {})
        metadata.update(
            {
                "router_writer_id": writer_id,
                "router_source": source,
                "router_decision": decision,
                "router_target_bank": target_bank,
            }
        )
        copied["metadata"] = metadata
        rewritten["items"].append(copied)
    return rewritten


def _string_projection(value: Any) -> Any:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [_string_projection(entry) for entry in value]
    if isinstance(value, dict):
        return {str(key): _string_projection(entry) for key, entry in value.items()}
    return None


def recalled_content_digest(result: dict[str, Any]) -> str:
    return sha256_hex(
        canonical_json(
            {
                "id": _string_projection(result.get("id")),
                "text": _string_projection(result.get("text")),
            }
        )
    )


def _recalled_audit_digest(result: dict[str, Any]) -> str:
    try:
        return sha256_hex(canonical_json(_string_projection(result)))
    except ValueError:
        return sha256_hex(repr(result))


def _audit_digest(value: Any) -> str:
    try:
        return sha256_hex(canonical_json(value))
    except ValueError:
        return sha256_hex(repr(value))


class RouterPolicy:
    def __init__(
        self, registry: Any, hindsight: Any, limits: Any, quarantine_store: Any, repository: Any
    ) -> None:
        self.registry = registry
        self.hindsight = hindsight
        self.limits = limits
        self.store = quarantine_store
        self.repository = repository
        self.security_event_identities = SecurityEventIdentityCap()

    async def retain(self, writer_id: str, body: dict[str, Any], source: str = "openclaw") -> Any:
        writer = self.registry.writers.get(writer_id)
        if writer is None:
            return await self._quarantine_retain(writer_id, source, "unknown_writer", body)
        scan = scan_retain_body(body)
        if not scan.safe:
            return await self._quarantine_retain(
                writer_id, source, "suspicious_content", body, writer.write_bank, scan
            )
        rewritten = prepare_retain_body(body, writer_id, source, writer.write_bank)
        await self.limits.consume_retain(writer_id)
        return await self.hindsight.retain(writer.write_bank, rewritten)

    async def recall(
        self, writer_id: str, body: dict[str, Any], source: str = "openclaw"
    ) -> dict[str, Any]:
        writer = self.registry.writers.get(writer_id)
        if writer is None:
            await self._quarantine_recall_or_degrade(writer_id, source, "unknown_writer", body)
            return {"results": []}
        scan = scan_recall_body(body)
        if not scan.safe:
            await self._quarantine_recall_or_degrade(
                writer_id, source, "suspicious_query", body, list(writer.read_banks), scan
            )
            return {"results": []}
        await self.limits.consume_recall(writer_id)
        responses = await self._recall_from_banks(writer_id, list(writer.read_banks), body)
        results: list[dict[str, Any]] = []
        for bank_id, response in responses:
            for result in response.get("results", []):
                if await self._allow_recalled_or_degrade(writer_id, source, bank_id, result):
                    results.append(result)
        combined: dict[str, Any] = {"results": results}
        for field in _RECALL_RESPONSE_MAP_FIELDS:
            merged: dict[str, Any] = {}
            present = False
            for _, response in responses:
                value = response.get(field)
                if isinstance(value, dict):
                    merged.update(value)
                    present = True
            if present:
                combined[field] = merged
        return combined

    async def deny_endpoint(
        self, method: str, path: str, writer_id: str | None = None
    ) -> dict[str, str]:
        dedupe = self.security_event_identities.resolve(
            writer_id, security_event_dedupe_key(method, path)
        )
        await self._quarantine(
            {
                "writerId": writer_id,
                "source": "http",
                "kind": "security_event",
                "reason": "denied_endpoint",
                "dedupeKey": dedupe,
                "payload": {"action": "denied_endpoint", "method": method, "path": path},
            }
        )
        return {"error": "endpoint denied by memory-router policy"}

    async def _recall_from_banks(
        self, writer_id: str, banks: list[str], body: dict[str, Any]
    ) -> list[tuple[str, dict[str, Any]]]:
        outcomes = await asyncio.gather(
            *(self.hindsight.recall(bank, body) for bank in banks), return_exceptions=True
        )
        responses: list[tuple[str, dict[str, Any]]] = []
        for bank, outcome in zip(banks, outcomes, strict=False):
            if isinstance(outcome, BaseException):
                if not isinstance(outcome, HindsightGatewayError):
                    raise outcome
                self._log_degradation(
                    "bank_unavailable",
                    {"writer_id": writer_id, "bank_id": bank, **outcome.details()},
                )
                continue
            responses.append((bank, cast(dict[str, Any], outcome)))
        return responses

    async def _allow_recalled_or_degrade(
        self, writer_id: str, source: str, bank_id: str, result: dict[str, Any]
    ) -> bool:
        try:
            return await self._allow_recalled(writer_id, source, bank_id, result)
        except ValueError:
            try:
                await self._quarantine_oversized_recalled(writer_id, source, bank_id, result)
            except HttpError as placeholder_exc:
                if not self._quarantine_unavailable(placeholder_exc):
                    raise
                self._log_degradation(
                    "quarantine_placeholder_unavailable",
                    {
                        "writer_id": writer_id,
                        "bank_id": bank_id,
                        "memory_id": result.get("id"),
                        "status": placeholder_exc.status,
                        "code": placeholder_exc.code,
                    },
                )
            return False
        except HttpError as exc:
            if exc.status == 413 and exc.code == "quarantine_item_too_large":
                try:
                    await self._quarantine_oversized_recalled(writer_id, source, bank_id, result)
                except HttpError as placeholder_exc:
                    if not self._quarantine_unavailable(placeholder_exc):
                        raise
                    self._log_degradation(
                        "quarantine_placeholder_unavailable",
                        {
                            "writer_id": writer_id,
                            "bank_id": bank_id,
                            "memory_id": result.get("id"),
                            "status": placeholder_exc.status,
                            "code": placeholder_exc.code,
                        },
                    )
                return False
            if not self._quarantine_unavailable(exc):
                raise
            self._log_degradation(
                "quarantine_write_unavailable",
                {
                    "writer_id": writer_id,
                    "bank_id": bank_id,
                    "memory_id": result.get("id"),
                    "status": exc.status,
                    "code": exc.code,
                },
            )
            return False

    async def _allow_recalled(
        self, writer_id: str, source: str, bank_id: str, result: dict[str, Any]
    ) -> bool:
        state = await self.repository.find_memory_state(bank_id, str(result["id"]))
        digest = recalled_content_digest(result)
        if state and state["status"] in {
            "reviewed_blocked",
            "review_in_progress",
            "review_side_effect_started",
            "review_side_effect_completed",
        }:
            return False
        if state and state["status"] == "reviewed_allowed":
            if state.get("source_content_sha256") == digest:
                volatile = {
                    key: value for key, value in result.items() if key not in {"id", "text"}
                }
                scan = scan_recall_result(volatile)
                if scan.safe:
                    return True
                await self._quarantine_recalled(writer_id, source, bank_id, result, digest, scan)
                return False
            scan = scan_recall_result(result)
            await self._quarantine_recalled(writer_id, source, bank_id, result, digest, scan)
            return False
        scan = scan_recall_result(result)
        if state and state["status"] in {"pending", "postponed"}:
            if state.get("source_content_sha256") == digest:
                return False
            await self._quarantine_recalled(writer_id, source, bank_id, result, digest, scan)
            return False
        if scan.safe:
            return True
        await self._quarantine_recalled(writer_id, source, bank_id, result, digest, scan)
        return False

    async def _quarantine_recalled(
        self,
        writer_id: str,
        source: str,
        bank_id: str,
        result: dict[str, Any],
        digest: str,
        scan: SafetyResult,
    ) -> None:
        payload: dict[str, Any] = {
            "action": "recalled_memory",
            "bank_id": bank_id,
            "result": result,
        }
        payload = self._with_transformations(payload, scan)
        await self._quarantine(
            {
                "writerId": writer_id,
                "source": source,
                "kind": "recalled_memory",
                "reason": "recalled_suspicious_memory",
                "sourceBank": bank_id,
                "sourceMemoryId": result["id"],
                "sourceContentSha256": digest,
                "payload": payload,
            }
        )

    async def _quarantine_oversized_recalled(
        self, writer_id: str, source: str, bank_id: str, result: dict[str, Any]
    ) -> None:
        digest = _recalled_audit_digest(result)
        scan = scan_recall_result(result)
        memory_id = str(result.get("id", "unknown"))
        await self._quarantine(
            {
                "writerId": writer_id,
                "source": source,
                "kind": "security_event",
                "reason": "recalled_suspicious_memory",
                "dedupeKey": f"oversized-recalled:{bank_id}:{memory_id}:{digest}",
                "payload": {
                    "action": "recalled_memory_too_large",
                    "bank_id": bank_id,
                    "memory_id": memory_id,
                    "content_sha256": digest,
                    "findings": [finding.public() for finding in scan.findings],
                },
            }
        )

    async def _quarantine_oversized_recall_request(
        self,
        writer_id: str,
        source: str,
        reason: str,
        body: dict[str, Any],
        scan: SafetyResult | None,
    ) -> None:
        digest = _audit_digest(body)
        findings = [] if scan is None else [finding.public() for finding in scan.findings]
        await self._quarantine(
            {
                "writerId": writer_id,
                "source": source,
                "kind": "security_event",
                "reason": reason,
                "dedupeKey": f"oversized-recall:{writer_id}:{reason}:{digest}",
                "payload": {
                    "action": "recall_request_too_large",
                    "writer_id": writer_id,
                    "content_sha256": digest,
                    "findings": findings,
                },
            }
        )

    async def _quarantine_retain(
        self,
        writer_id: str,
        source: str,
        reason: str,
        body: dict[str, Any],
        target_bank: str | None = None,
        scan: SafetyResult | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"action": "retain", "writer_id": writer_id, "body": body}
        payload = self._with_transformations(payload, scan)
        result = await self._quarantine(
            {
                "writerId": writer_id,
                "source": source,
                "kind": "retain_request",
                "reason": reason,
                "dedupeKey": request_dedupe_key(
                    "retain_request",
                    writer_id,
                    target_bank,
                    {"action": "retain", "writer_id": writer_id, "body": body},
                ),
                "payload": payload,
            }
        )
        response: dict[str, Any] = {
            "queued": True,
            "reason": reason,
            "quarantine_id": result["quarantine_id"],
        }
        if scan is not None:
            response["findings"] = [finding.public() for finding in scan.findings]
        return response

    async def _quarantine_recall_or_degrade(
        self,
        writer_id: str,
        source: str,
        reason: str,
        body: dict[str, Any],
        target_banks: list[str] | None = None,
        scan: SafetyResult | None = None,
    ) -> None:
        try:
            payload: dict[str, Any] = {"action": "recall", "writer_id": writer_id, "body": body}
            payload = self._with_transformations(payload, scan)
            target = ",".join(sorted(target_banks)) if target_banks else None
            await self._quarantine(
                {
                    "writerId": writer_id,
                    "source": source,
                    "kind": "recall_request",
                    "reason": reason,
                    "dedupeKey": request_dedupe_key(
                        "recall_request",
                        writer_id,
                        target,
                        {"action": "recall", "writer_id": writer_id, "body": body},
                    ),
                    "payload": payload,
                }
            )
        except HttpError as exc:
            if exc.status == 413 and exc.code == "quarantine_item_too_large":
                try:
                    await self._quarantine_oversized_recall_request(
                        writer_id, source, reason, body, scan
                    )
                except HttpError as placeholder_exc:
                    if not self._quarantine_unavailable(placeholder_exc):
                        raise
                    self._log_degradation(
                        "quarantine_placeholder_unavailable",
                        {
                            "writer_id": writer_id,
                            "reason": reason,
                            "status": placeholder_exc.status,
                            "code": placeholder_exc.code,
                        },
                    )
                return
            if not self._quarantine_unavailable(exc):
                raise
            self._log_degradation(
                "quarantine_write_unavailable",
                {"writer_id": writer_id, "reason": reason, "status": exc.status, "code": exc.code},
            )

    async def _quarantine(self, values: dict[str, Any]) -> dict[str, str]:
        return cast(dict[str, str], await self.store.put({"timestamp": iso_now(), **values}))

    @staticmethod
    def _with_transformations(payload: dict[str, Any], scan: SafetyResult | None) -> dict[str, Any]:
        if scan is None or not scan.transformations:
            return payload
        return {**payload, "safety": {"transformations": sorted(scan.transformations)}}

    @staticmethod
    def _quarantine_unavailable(error: HttpError) -> bool:
        return (
            error.status in {507, 429}
            or (error.status == 413 and error.code == "quarantine_item_too_large")
            or (
                error.status == 409
                and error.code in {"quarantine_request_in_review", "quarantine_item_in_review"}
            )
        )

    @staticmethod
    def _log_degradation(event: str, details: dict[str, Any]) -> None:
        logger.warning(
            "recall degraded event=%s request_id=%s details=%s",
            event,
            current_request_id(),
            details,
        )
