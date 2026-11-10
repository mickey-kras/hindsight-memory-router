from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .blocked_exceptions import AUTHORIZATION_CONTEXT, ordered_content_digest, ordered_content_json
from .canonical import canonical_json, sha256_hex
from .review_capture import contains_credentials
from .security_models import SafetyResult

if TYPE_CHECKING:
    from .policy import RouterPolicy


def blocked_content_key(
    policy: RouterPolicy,
    scope: tuple[str, str, str, str | None],
    payload: dict[str, Any],
    scan: SafetyResult,
    scanner_policy: Callable[[], str],
) -> str | None:
    writer_id, source, reason, bank_id = scope
    if any(finding.reason == "span_limit" for finding in scan.findings):
        return None
    if contains_credentials(payload, getattr(policy.hindsight, "api_key", None)):
        return None
    context = payload.get("context", {})
    if context.get("credential_bearing"):
        return None
    if len(canonical_json(payload).encode()) > getattr(
        getattr(policy.store, "limits", None), "max_item_bytes", 1_048_576
    ):
        return None
    authorization = AUTHORIZATION_CONTEXT.get()
    if authorization is None:
        writer = policy.registry.writers.get(writer_id)
        if writer is None:
            return None
        authorization = {"legacy_writer": writer.model_dump(mode="json")}
    return sha256_hex(
        canonical_json(
            {
                "principal": writer_id,
                "source": source,
                "reason": reason,
                "bank": bank_id,
                "payload_sha256": ordered_content_digest(payload),
                "authorization": authorization,
                "scanner_policy": scanner_policy(),
                "findings": [
                    {
                        "matched": f.matched,
                        "reason": f.reason,
                        "detector": f.detector,
                        "hits": list(f.hits),
                    }
                    for f in scan.findings
                ],
            }
        )
    )


async def capture_blocked_content(
    policy: RouterPolicy,
    scope: tuple[str, str, str, str | None],
    payload: dict[str, Any],
    scan: SafetyResult | None,
    scanner_policy: Callable[[], str],
) -> None:
    writer_id, source, reason, bank_id = scope
    try:
        if scan is not None and any(finding.reason == "span_limit" for finding in scan.findings):
            policy._log_degradation(
                "blocked_content_capture_unavailable", {"error_type": "scan_limit"}
            )
            return
        context = payload.get("context", {})
        if contains_credentials(payload, getattr(policy.hindsight, "api_key", None)) or context.get(
            "credential_bearing"
        ):
            policy._log_degradation(
                "blocked_content_capture_unavailable", {"error_type": "provider_credentials"}
            )
            return
        exception_key = (
            policy.blocked_content_key(writer_id, source, reason, bank_id, payload, scan)
            if scan is not None
            else None
        )
        if reason in {
            "recalled_suspicious_aggregate",
            "recalled_suspicious_supplemental",
            "openclaw_suspicious_provider_response",
        }:
            evidence = payload.get("response", payload.get("entry"))
            if (
                reason == "recalled_suspicious_supplemental"
                and payload.get("entry_key") is not None
            ):
                evidence = {payload["entry_key"]: evidence}
            if contains_credentials(evidence, getattr(policy.hindsight, "api_key", None)):
                policy._log_degradation(
                    "blocked_content_capture_unavailable",
                    {
                        "writer_id": writer_id,
                        "reason": reason,
                        "error_type": "provider_credentials",
                    },
                )
                return
        review_banks = context.get("bank_ids", [bank_id] if bank_id is not None else [])
        await policy.quarantine_security_event(
            {
                "writerId": writer_id,
                "source": source,
                "kind": "blocked_content",
                "sourceContentSha256": exception_key,
                "reviewBanks": review_banks,
                "reason": reason,
                "bankId": bank_id,
                "payload": {
                    **payload,
                    "ordered_payload_json": ordered_content_json(payload),
                    "principal_id": writer_id,
                    "authorization_scope": {"bank_id": bank_id, "source": source},
                    "decision_scope": "exact_content_and_context"
                    if exception_key
                    else "classification_only",
                    "policy": scanner_policy(),
                },
            }
        )
    except Exception as exc:
        policy._log_degradation(
            "blocked_content_capture_unavailable",
            {"writer_id": writer_id, "reason": reason, "error_type": type(exc).__name__},
        )
