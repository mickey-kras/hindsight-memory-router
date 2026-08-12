from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote, urlencode

from .canonical import canonical_json, sha256_hex
from .errors import HttpError
from .hindsight import HindsightGatewayError
from .observability import current_request_id
from .openclaw_contracts import validate_openclaw_response
from .security import SafetyResult, scan_recall_body, scan_recall_result, scan_retain_body

logger = logging.getLogger(__name__)

_WRITE_METHODS = {"PUT", "PATCH", "POST", "DELETE"}


class OpenClawFacade:
    """Policy-gated facade for the Hindsight endpoints used by the OpenClaw plugin."""

    def __init__(self, policy: Any) -> None:
        self.policy = policy

    async def forward(
        self,
        *,
        writer_id: str,
        method: str,
        resource: str,
        body: dict[str, Any] | None = None,
        query: list[tuple[str, str]] | None = None,
        mental_model_id: str | None = None,
        read_operation: bool = False,
    ) -> Any:
        writer = self.policy.registry.writers.get(writer_id)
        if writer is None:
            await self._audit(
                writer_id,
                "openclaw_unknown_writer",
                {"method": method, "resource": resource},
                None,
            )
            raise HttpError(404, "unknown_writer", "writer is not registered")

        request_evidence: dict[str, Any] = {
            "bank_id": writer_id,
            "resource": resource,
            "query": query or [],
        }
        if mental_model_id is not None:
            request_evidence["mental_model_id"] = mental_model_id
        if body is not None:
            request_evidence["body"] = body

        scan = (
            scan_recall_body(request_evidence)
            if read_operation
            else scan_retain_body(request_evidence)
        )
        if not scan.safe:
            await self._audit(writer_id, "openclaw_suspicious_request", request_evidence, scan)
            raise HttpError(422, "suspicious_content", "request blocked by memory-router policy")

        if read_operation:
            await self.policy.limits.consume_recall(writer_id)
        elif method in _WRITE_METHODS:
            await self.policy.limits.consume_retain(writer_id)

        bank = quote(writer.write_bank, safe="")
        path = f"/v1/default/banks/{bank}"
        if resource:
            path += f"/{resource}"
        if mental_model_id is not None:
            path += f"/{quote(mental_model_id, safe='')}"
        if query:
            path += "?" + urlencode(query)

        operation = resource.replace("/", "_") or "bank"
        value = await self.policy.hindsight.openclaw_request(
            f"openclaw_{operation}", method, path, body
        )
        if value is not None:
            response_scan = scan_recall_result({"response": value})
            if not response_scan.safe:
                await self._audit(
                    writer_id,
                    "openclaw_suspicious_provider_response",
                    {"resource": resource, "response": value},
                    response_scan,
                )
                raise HttpError(
                    502,
                    "hindsight_unsafe_response",
                    "upstream memory service returned unsafe content",
                )
        try:
            validate_openclaw_response(method, resource, mental_model_id, value)
        except ValueError as exc:
            raise HindsightGatewayError(
                "invalid-response", operation=f"openclaw_{operation}", method=method
            ) from exc
        if method == "DELETE" and resource == "mental-models" and value is None:
            return {}
        return value

    async def _audit(
        self,
        writer_id: str,
        reason: str,
        value: Any,
        scan: SafetyResult | None,
    ) -> None:
        try:
            digest = sha256_hex(canonical_json(value))
        except (ValueError, RecursionError):
            digest = sha256_hex(repr(type(value)))
        findings = [] if scan is None else [finding.public() for finding in scan.findings]
        try:
            await self.policy._quarantine(  # noqa: SLF001 - same package policy boundary
                {
                    "writerId": writer_id,
                    "source": "openclaw",
                    "kind": "security_event",
                    "reason": reason,
                    "dedupeKey": f"{reason}:{writer_id}:{digest}",
                    "payload": {
                        "action": reason,
                        "content_sha256": digest,
                        "findings": findings,
                    },
                }
            )
        except Exception as exc:
            # Blocking is independent from audit availability; never log raw payload/content.
            logger.warning(
                "openclaw security audit unavailable request_id=%s reason=%s writer_id=%s error_type=%s",
                current_request_id(),
                reason,
                writer_id,
                type(exc).__name__,
            )
