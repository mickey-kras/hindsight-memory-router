from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .errors import HttpError
from .hindsight import HindsightGatewayError
from .models import RecallBody, RecallResult, RetainBody, WriterRegistry
from .quarantine.crypto import canonical_json
from .quarantine.repository import QuarantineRepository
from .quarantine.store import EncryptedDatabaseQuarantineStore, QuarantineInput
from .rate_limits import HindsightLimits
from .security import SafetyFinding, SafetyResult, scan_content, scan_recall_result, scan_retain_body

MAX_SECURITY_EVENT_IDENTITIES = 64


class SecurityEventIdentityCap:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def resolve(self, writer_id: str | None, base_key: str) -> str:
        scoped = f"{writer_id or 'anonymous'}:{base_key}"
        if scoped in self._seen:
            return scoped
        if len(self._seen) >= MAX_SECURITY_EVENT_IDENTITIES:
            return "aggregate"
        self._seen.add(scoped)
        return scoped


class MemoryRouterPolicy:
    def __init__(
        self,
        registry: WriterRegistry,
        hindsight: Any,
        quarantine_store: EncryptedDatabaseQuarantineStore,
        repository: QuarantineRepository,
        limits: HindsightLimits,
    ) -> None:
        self.registry = registry
        self.hindsight = hindsight
        self.quarantine_store = quarantine_store
        self.repository = repository
        self.limits = limits
        self._security_event_identities = SecurityEventIdentityCap()

    async def retain(
        self, writer_id: str, body: RetainBody, source: str = "openclaw"
    ) -> Any:
        writer = self.registry.writers.get(writer_id)
        if writer is None:
            return await self._quarantine_retain(
                writer_id=writer_id,
                source=source,
                reason="unknown_writer",
                body=body,
            )

        safety = scan_retain_body(body)
        if not safety.safe:
            return await self._quarantine_retain(
                writer_id=writer_id,
                source=source,
                reason="suspicious_content",
                body=body,
                target_bank=writer.write_bank,
                findings=safety.findings,
                transformations=safety.transformations,
            )

        forwarded = body.model_dump_wire()
        forwarded_items: list[dict[str, Any]] = []
        for item in body.items:
            raw = item.model_dump(exclude_none=True)
            raw["metadata"] = {
                **dict(raw.get("metadata") or {}),
                "router_writer_id": writer_id,
                "router_source": source,
                "router_decision": "allowed",
                "router_target_bank": writer.write_bank,
            }
            forwarded_items.append(raw)
        forwarded["items"] = forwarded_items
        await self.limits.consume_retain(writer_id)
        return await self.hindsight.retain(writer.write_bank, forwarded)

    async def recall(
        self, writer_id: str, body: RecallBody, source: str = "openclaw"
    ) -> dict[str, Any]:
        writer = self.registry.writers.get(writer_id)
        if writer is None:
            await self._quarantine_recall_or_degrade(
                writer_id=writer_id,
                source=source,
                reason="unknown_writer",
                body=body,
            )
            return {"results": []}

        safety = scan_content(body.query, operation="write")
        if not safety.safe:
            await self._quarantine_recall_or_degrade(
                writer_id=writer_id,
                source=source,
                reason="suspicious_query",
                body=body,
                target_banks=writer.read_banks,
                transformations=safety.transformations,
            )
            return {"results": []}

        await self.limits.consume_recall(writer_id)
        outcomes = await asyncio.gather(
            *(self.hindsight.recall(bank, body) for bank in writer.read_banks),
            return_exceptions=True,
        )
        results: list[dict[str, Any]] = []
        for bank, outcome in zip(writer.read_banks, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                if not isinstance(outcome, HindsightGatewayError):
                    raise outcome
                self._log_recall_degradation(
                    "bank_unavailable",
                    {
                        "writer_id": writer_id,
                        "bank_id": bank,
                        **outcome.details(),
                    },
                )
                continue
            for result in outcome.results:
                if await self._allow_recalled_result_or_degrade(
                    writer_id, source, bank, result
                ):
                    results.append(result.model_dump(exclude_none=True))
        return {"results": results}

    async def deny_endpoint(
        self, method: str, path: str, writer_id: str | None = None
    ) -> dict[str, str]:
        dedupe = self._security_event_identities.resolve(
            writer_id, f"{method.upper()}:{_normalize_security_event_path(path)}"
        )
        await self.quarantine_store.put(
            QuarantineInput(
                timestamp=_now_iso(),
                kind="security_event",
                reason="denied_endpoint",
                writer_id=writer_id,
                source="http",
                dedupe_key=dedupe,
                payload={"action": "denied_endpoint", "method": method, "path": path},
            )
        )
        return {"error": "endpoint denied by memory-router policy"}

    async def _allow_recalled_result_or_degrade(
        self,
        writer_id: str,
        source: str,
        bank: str,
        result: RecallResult,
    ) -> bool:
        try:
            return await self._allow_recalled_result(writer_id, source, bank, result)
        except HttpError as error:
            if not _is_quarantine_unavailable(error):
                raise
            self._log_recall_degradation(
                "quarantine_write_unavailable",
                {
                    "writer_id": writer_id,
                    "bank_id": bank,
                    "memory_id": result.id,
                    "status": error.status,
                    "code": error.code,
                },
            )
            return False

    async def _allow_recalled_result(
        self,
        writer_id: str,
        source: str,
        bank: str,
        result: RecallResult,
    ) -> bool:
        state = await self.repository.find_memory_state(bank, result.id)
        content_hash = hashlib.sha256(result.text.encode("utf-8")).hexdigest()
        safety = scan_recall_result(result)

        if state is not None and state.status == "reviewed_blocked":
            return False
        if state is not None and state.status == "reviewed_allowed":
            if state.source_content_sha256 == content_hash:
                return True
            await self._quarantine_recalled(
                writer_id, source, bank, result, content_hash, safety.transformations
            )
            return False
        if state is not None and state.status in {"pending", "postponed"}:
            if state.source_content_sha256 != content_hash:
                await self._quarantine_recalled(
                    writer_id, source, bank, result, content_hash, safety.transformations
                )
            return False

        if safety.safe:
            return True
        await self._quarantine_recalled(
            writer_id, source, bank, result, content_hash, safety.transformations
        )
        return False

    async def _quarantine_recalled(
        self,
        writer_id: str,
        source: str,
        bank: str,
        result: RecallResult,
        content_hash: str,
        transformations: tuple[str, ...],
    ) -> None:
        payload: dict[str, Any] = {
            "action": "recalled_memory",
            "bank_id": bank,
            "result": result.model_dump(exclude_none=True),
        }
        payload.update(_transformation_payload(transformations))
        await self.quarantine_store.put(
            QuarantineInput(
                timestamp=_now_iso(),
                kind="recalled_memory",
                reason="recalled_suspicious_memory",
                writer_id=writer_id,
                source=source,
                source_bank=bank,
                source_memory_id=result.id,
                source_content_sha256=content_hash,
                payload=payload,
            )
        )

    async def _quarantine_recall_or_degrade(
        self,
        *,
        writer_id: str,
        source: str,
        reason: str,
        body: RecallBody,
        target_banks: list[str] | None = None,
        transformations: tuple[str, ...] = (),
    ) -> None:
        try:
            payload: dict[str, Any] = {
                "action": "recall",
                "writer_id": writer_id,
                "body": body.model_dump(exclude_none=True),
            }
            dedupe = request_dedupe_key(
                "recall_request",
                writer_id,
                ",".join(sorted(target_banks)) if target_banks is not None else None,
                payload,
            )
            payload.update(_transformation_payload(transformations))
            await self.quarantine_store.put(
                QuarantineInput(
                    timestamp=_now_iso(),
                    kind="recall_request",
                    reason=reason,
                    writer_id=writer_id,
                    source=source,
                    dedupe_key=dedupe,
                    payload=payload,
                )
            )
        except HttpError as error:
            if not _is_quarantine_unavailable(error):
                raise
            self._log_recall_degradation(
                "quarantine_write_unavailable",
                {"writer_id": writer_id, "reason": reason, "status": error.status, "code": error.code},
            )

    async def _quarantine_retain(
        self,
        *,
        writer_id: str,
        source: str,
        reason: str,
        body: RetainBody,
        target_bank: str | None = None,
        findings: tuple[SafetyFinding, ...] | None = None,
        transformations: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "action": "retain",
            "writer_id": writer_id,
            "body": body.model_dump_wire(),
        }
        dedupe = request_dedupe_key(
            "retain_request", writer_id, target_bank, payload
        )
        payload.update(_transformation_payload(transformations))
        stored = await self.quarantine_store.put(
            QuarantineInput(
                timestamp=_now_iso(),
                kind="retain_request",
                reason=reason,
                writer_id=writer_id,
                source=source,
                dedupe_key=dedupe,
                payload=payload,
            )
        )
        response: dict[str, Any] = {
            "queued": True,
            "reason": reason,
            "quarantine_id": stored["quarantine_id"],
        }
        if findings is not None:
            response["findings"] = [asdict(finding) for finding in findings]
        return response

    def _log_recall_degradation(self, event: str, details: dict[str, Any]) -> None:
        sys.stderr.write(
            f"memory-router recall degraded: {json.dumps({'event': event, **details}, separators=(',', ':'))}\n"
        )


def _is_quarantine_unavailable(error: HttpError) -> bool:
    return error.status in {429, 507} or (
        error.status == 409 and error.code == "quarantine_request_in_review"
    )


def _transformation_payload(transformations: tuple[str, ...]) -> dict[str, Any]:
    if not transformations:
        return {}
    return {"safety": {"transformations": list(transformations)}}


def request_dedupe_key(
    kind: str, writer_id: str | None, target: str | None, payload: Any
) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "kind": kind,
                "writer_id": writer_id,
                "target": target,
                "payload": payload,
            }
        )
    ).hexdigest()


def _normalize_security_event_path(path: str) -> str:
    without_query = path.split("?", 1)[0].split("#", 1)[0]
    normalized = without_query.lower().rstrip("/")
    return normalized or "/"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
