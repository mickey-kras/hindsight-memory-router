from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote, urlencode

from .canonical import canonical_json, sha256_hex
from .errors import HttpError
from .facade_routes import FacadeRoute
from .hindsight import HindsightGatewayError
from .logging import log_event
from .observability import current_request_id
from .openclaw_contracts import validate_facade_response, validate_openclaw_response
from .scan_executor import scan_facade_response, scan_request, scan_unavailable
from .security import SafetyResult

logger = logging.getLogger(__name__)


class OpenClawFacade:
    def __init__(self, policy: Any) -> None:
        self.policy = policy

    async def forward(
        self,
        *,
        route: FacadeRoute,
        writer_id: str,
        params: dict[str, str],
        body: dict[str, Any] | None = None,
        query: list[tuple[str, str]] | None = None,
        bank_override: str | None = None,
        source: str = "openclaw",
    ) -> Any:
        target_bank = await self._target_bank(route, writer_id, bank_override, source)

        forwarded_query = [
            (key, value) for key, value in (query or []) if key in route.query_params
        ]
        _validate_required_query(route, forwarded_query)
        request_evidence: dict[str, Any] = {
            "bank_id": writer_id,
            "resource": route.resource,
            "query": [{"key": key, "value": value} for key, value in forwarded_query],
        }
        for name in route.params:
            request_evidence[name] = params[name]
        if body is not None:
            request_evidence["body"] = body

        self._validate_request_bounds(route, body)

        if route.read:
            await self.policy.limits.consume_recall(writer_id)
        else:
            await self.policy.limits.consume_retain(writer_id)

        # Route metadata and free-text query values are not persisted payload. Query
        # values decode valid Base64 but do not fail closed on ordinary URL syntax.
        await self._validate_safe_request(
            route, writer_id, source, request_evidence, forwarded_query, bank_override
        )
        path = _facade_path(route, target_bank, params, forwarded_query)

        value = await self.policy.hindsight.openclaw_request(
            f"openclaw_{route.operation}",
            route.method,
            path,
            body,
            expected_status=route.success_status,
            allow_empty_response=route.allow_empty_response,
        )
        if value is not None:
            await self._validate_safe_response(route, writer_id, source, value, bank_override)
        try:
            if route.strict_contract:
                validate_openclaw_response(
                    route.method, route.resource, params.get("mental_model_id"), value
                )
            else:
                validate_facade_response(
                    value, route.response, allow_empty=route.allow_empty_response
                )
        except ValueError as exc:
            raise HindsightGatewayError(
                "invalid-response", operation=f"openclaw_{route.operation}", method=route.method
            ) from exc
        return value

    async def _validate_safe_request(
        self,
        route: FacadeRoute,
        writer_id: str,
        source: str,
        evidence: dict[str, Any],
        query: list[tuple[str, str]],
        bank_id: str | None = None,
    ) -> None:
        scan_input = {
            key: value for key, value in evidence.items() if key not in {"resource", "query"}
        }
        scan = await scan_request(
            scan_input,
            operation="recall" if route.request_scan == "recall" else "retain",
            writer_id=writer_id,
            query=query,
        )
        if scan.safe:
            return
        await self._audit(writer_id, "openclaw_suspicious_request", evidence, scan, source, bank_id)
        raise HttpError(422, "suspicious_content", "request blocked by memory-router policy")

    async def _target_bank(
        self, route: FacadeRoute, writer_id: str, override: str | None, source: str
    ) -> str:
        if override is not None:
            return override
        writer = self.policy.registry.writers.get(writer_id)
        if writer is not None:
            return str(writer.write_bank)
        await self._audit(
            writer_id,
            "openclaw_unknown_writer",
            {"method": route.method, "resource": route.resource},
            None,
            source,
        )
        raise HttpError(404, "unknown_writer", "writer is not registered")

    def _validate_request_bounds(self, route: FacadeRoute, body: dict[str, Any] | None) -> None:
        if body is None:
            return
        if route.resource == "reflect":
            self.policy.limits.assert_recall_bounds(body)
        if route.template != "memories/dry-run-extract":
            return
        if not isinstance(body.get("items"), list):
            raise HttpError(400, "invalid_request", "items must be an array")
        self.policy.limits.assert_retain_bounds(body)

    async def _validate_safe_response(
        self,
        route: FacadeRoute,
        writer_id: str,
        source: str,
        value: Any,
        bank_id: str | None = None,
    ) -> None:
        response_scan = await scan_facade_response(value, writer_id=writer_id)
        if _only_scan_limit_findings(response_scan):
            error_kind = (
                "timeout"
                if any(finding.matched == "facade_time_limit" for finding in response_scan.findings)
                else "response-too-large"
            )
            raise scan_unavailable(
                "response exceeded safety scan limits",
                error_kind=error_kind,
                writer_id=writer_id,
            )
        if response_scan.safe:
            return
        await self._audit(
            writer_id,
            "openclaw_suspicious_provider_response",
            {"resource": route.resource, "response": value},
            response_scan,
            source,
            bank_id,
        )
        raise HttpError(
            502,
            "hindsight_unsafe_response",
            "upstream memory service returned unsafe content",
        )

    async def _audit(
        self,
        writer_id: str,
        reason: str,
        value: Any,
        scan: SafetyResult | None,
        source: str = "openclaw",
        bank_id: str | None = None,
    ) -> None:
        try:
            digest = sha256_hex(canonical_json(value))
        except (ValueError, RecursionError):
            digest = sha256_hex(repr(type(value)))
        findings = [] if scan is None else [finding.public() for finding in scan.findings]
        try:
            await self.policy.quarantine_security_event(
                {
                    "writerId": writer_id,
                    "source": source,
                    "kind": "security_event",
                    "reason": reason,
                    "bankId": bank_id,
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
            log_event(
                logger,
                "error",
                "openclaw_security_audit_failed",
                error=exc,
                request_id=current_request_id(),
                operation="security_audit",
                error_kind="unexpected",
                outcome="failed",
                route_class="openclaw",
                writer_id=writer_id,
                reason=reason,
            )


def _only_scan_limit_findings(scan: SafetyResult) -> bool:
    limits = {"facade_field_limit", "facade_time_limit"}
    return bool(scan.findings) and all(finding.matched in limits for finding in scan.findings)


def _validate_required_query(route: FacadeRoute, query: list[tuple[str, str]]) -> None:
    supplied = {key for key, _ in query}
    missing = [name for name in route.required_query_params if name not in supplied]
    if missing:
        raise HttpError(400, "invalid_request", f"missing required query parameter: {missing[0]}")


def _facade_path(
    route: FacadeRoute,
    bank_id: str,
    params: dict[str, str],
    query: list[tuple[str, str]],
) -> str:
    suffix = route.template
    for name in route.params:
        suffix = suffix.replace("{" + name + "}", quote(params[name], safe=""))
    path = f"/v1/default/banks/{quote(bank_id, safe='')}"
    if suffix:
        path += f"/{suffix}"
    if query:
        path += "?" + urlencode(query)
    return path
