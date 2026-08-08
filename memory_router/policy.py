from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime
from typing import Any, cast

from .canonical import sha256_hex
from .dedupe import SecurityEventIdentityCap, request_dedupe_key, security_event_dedupe_key
from .errors import HttpError
from .hindsight import HindsightGatewayError
from .security import SafetyResult, scan_content, scan_recall_result, scan_retain_body


def iso_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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
        rewritten = dict(body)
        rewritten["items"] = []
        for item in body["items"]:
            copied = dict(item)
            metadata = dict(copied.get("metadata") or {})
            metadata.update(
                {
                    "router_writer_id": writer_id,
                    "router_source": source,
                    "router_decision": "allowed",
                    "router_target_bank": writer.write_bank,
                }
            )
            copied["metadata"] = metadata
            rewritten["items"].append(copied)
        await self.limits.consume_retain(writer_id)
        return await self.hindsight.retain(writer.write_bank, rewritten)

    async def recall(
        self, writer_id: str, body: dict[str, Any], source: str = "openclaw"
    ) -> dict[str, Any]:
        writer = self.registry.writers.get(writer_id)
        if writer is None:
            await self._quarantine_recall_or_degrade(writer_id, source, "unknown_writer", body)
            return {"results": []}
        scan = scan_content(body.get("query", ""), operation="read", key="recall.query")
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
        return {"results": results}

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
        except HttpError as exc:
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
        digest = sha256_hex(str(result.get("text", "")))
        scan = scan_recall_result(result)
        if state and state["status"] == "reviewed_blocked":
            return False
        if state and state["status"] == "reviewed_allowed":
            if state.get("source_content_sha256") == digest:
                return True
            await self._quarantine_recalled(writer_id, source, bank_id, result, digest, scan)
            return False
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
        return error.status in {507, 429} or (
            error.status == 409 and error.code == "quarantine_request_in_review"
        )

    @staticmethod
    def _log_degradation(event: str, details: dict[str, Any]) -> None:
        sys.stderr.write(
            "memory-router recall degraded: "
            + json.dumps({"event": event, **details}, separators=(",", ":"))
            + "\n"
        )
