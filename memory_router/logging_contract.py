from __future__ import annotations

import hashlib
import logging
import math
import re
from typing import Any

from .facade_routes import FACADE_ROUTES
from .principals import SCOPE_VOCABULARY

SAFE_FIELDS = frozenset(
    {
        "request_id",
        "operation",
        "upstream_method",
        "request_method",
        "error_kind",
        "error_fingerprint",
        "upstream_status",
        "http_status",
        "outcome",
        "request_duration_ms",
        "operation_duration_ms",
        "route_class",
        "writer_id",
        "principal",
        "token_key_id",
        "bank",
        "scope",
        "decision",
        "status",
        "latency_ms",
        "source",
        "partial",
        "reason",
        "timeout_ms",
        "suppressed",
    }
)
OUTPUT_FIELDS = frozenset({"event", "level", "timestamp", "logger", *SAFE_FIELDS})
LEVELS = {"info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}
EVENTS = frozenset(
    {
        "application_start_failed",
        "application_stop_failed",
        "application_started",
        "authentication_failed",
        "authentication_audit_failed",
        "authorization_decision",
        "principal_throttled",
        "principal_concurrency_release_failed",
        "principal_concurrency_unavailable",
        "principal_rate_unavailable",
        "auth_rate_unavailable",
        "admin_rate_unavailable",
        "bank_unavailable",
        "configuration_warning",
        "facade_scan_failed",
        "hindsight_readiness_failed",
        "hindsight_readiness_recovered",
        "hindsight_request_failed",
        "logging_contract_violation",
        "openclaw_security_audit_failed",
        "quarantine_placeholder_unavailable",
        "quarantine_sweeper_failed",
        "quarantine_write_unavailable",
        "recall_supplemental_audit_unavailable",
        "request_failed",
        "runtime_message",
        "storage_readiness_failed",
        "storage_readiness_recovered",
    }
)
ERROR_KINDS = frozenset(
    {
        "capacity",
        "conflict",
        "http",
        "invalid-credentials",
        "invalid-response",
        "network",
        "payload-too-large",
        "rate-limit",
        "response-too-large",
        "storage",
        "shutdown",
        "timeout",
        "unexpected",
        "worker-crash",
    }
)
OUTCOMES = frozenset({"failed", "degraded", "healthy", "unhealthy"})
ROUTE_CLASSES = frozenset(
    {"readiness", "liveness", "version", "admin", "memory", "openclaw", "unmatched"}
)
OPERATIONS = (
    frozenset(
        {
            "authenticate",
            "authorize",
            "configuration",
            "consume-principal-rate",
            "facade_scan",
            "health",
            "invalidate_memory",
            "manage-concurrency-lease",
            "quarantine_maintenance",
            "recall",
            "request",
            "release-concurrency-lease",
            "retain",
            "security_audit",
            "shutdown",
            "startup",
            "storage_health",
            "version",
        }
    )
    | SCOPE_VOCABULARY
    | frozenset(f"openclaw_{route.operation}" for route in FACADE_ROUTES)
)
METHODS = frozenset({"GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS"})
REASONS = frozenset(
    {
        "admin-cleanup-token-missing",
        "admin-read-token-missing",
        "admin-review-token-missing",
        "agent-claim-mismatch",
        "expired-token",
        "invalid-token-format",
        "revoked-token",
        "unknown-key-id",
        "wrong-secret",
        "anonymous-mode",
        "application-shutdown",
        "application-startup",
        "asgi-application-error",
        "http-protocol-error",
        "insecure-hindsight-transport",
        "legacy-admin-token",
        "direct-stdlib-log",
        "openclaw-suspicious-provider-response",
        "openclaw-suspicious-request",
        "openclaw-unknown-writer",
        "reserved-field",
        "router-token-missing",
        "runtime-other",
        "server-finished",
        "server-started",
        "server-running",
        "server-stopping",
        "unregistered-event",
    }
)
RESERVED_FIELDS = frozenset({"event", "level", "timestamp", "logger"})
THROTTLED_EVENTS = EVENTS - {
    "application_start_failed",
    "application_started",
    "authorization_decision",
    "configuration_warning",
    "principal_throttled",
    "hindsight_readiness_failed",
    "logging_contract_violation",
    "runtime_message",
    "storage_readiness_failed",
}
TEXT_LIMITS = {
    "request_id": 128,
    "operation": 64,
    "upstream_method": 16,
    "request_method": 16,
    "writer_id": 128,
    "principal": 128,
    "token_key_id": 64,  # nosec B105 - audit field name, not a credential
    "bank": 128,
    "scope": 64,
    "decision": 16,
    "source": 64,
    "logger": 128,
    "level": 16,
    "timestamp": 64,
    "event": 64,
}
INTEGER_FIELDS = frozenset({"upstream_status", "http_status", "timeout_ms", "suppressed", "status"})
DURATION_FIELDS = frozenset({"request_duration_ms", "operation_duration_ms", "latency_ms"})
BOOLEAN_FIELDS = frozenset({"partial"})
DECISIONS = frozenset({"allow", "deny"})
FINGERPRINT_PATTERN = re.compile(r"^(?:[A-Za-z][A-Za-z0-9.]{0,63}|site:[0-9a-f]{16})$")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
WRITER_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
LOGGER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")


def _opaque_text(value: Any, prefix: str) -> str:
    raw = safe_text(value, fallback="unavailable", limit=512)
    digest = hashlib.sha256(raw.encode(errors="replace")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def safe_text(value: Any, *, fallback: str, limit: int) -> str:
    try:
        return str(value)[:limit]
    except Exception:
        return fallback


def sanitize_output_field(key: str, value: Any) -> Any | None:
    if key == "logger":
        logger_name = safe_text(value, fallback="unavailable", limit=TEXT_LIMITS[key])
        return (
            logger_name if LOGGER_PATTERN.fullmatch(logger_name) else _opaque_text(value, "logger")
        )
    if key in TEXT_LIMITS:
        return safe_text(value, fallback="unavailable", limit=TEXT_LIMITS[key])
    if key in INTEGER_FIELDS:
        return (
            value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
        )
    if key in DURATION_FIELDS:
        return _nonnegative_number(value)
    if key in BOOLEAN_FIELDS:
        return value if isinstance(value, bool) else None
    if key in {"error_kind", "error_fingerprint", "outcome", "route_class", "reason"}:
        return safe_text(value, fallback="unavailable", limit=128)
    return None


def _nonnegative_number(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    numeric = float(value)
    return numeric if math.isfinite(numeric) and numeric >= 0 else None


def sanitize_fields(fields: dict[str, Any]) -> dict[str, Any]:
    safe_fields = {
        key: value for key, value in fields.items() if key in SAFE_FIELDS and value is not None
    }
    _sanitize_vocabularies(safe_fields)
    _sanitize_pattern_field(safe_fields, "error_fingerprint", FINGERPRINT_PATTERN, 80)
    _sanitize_pattern_field(
        safe_fields, "request_id", REQUEST_ID_PATTERN, 129, fallback="unavailable"
    )
    _sanitize_identifier(safe_fields, "writer_id", "writer")
    for id_field in ("principal", "token_key_id", "bank"):
        _sanitize_identifier(safe_fields, id_field, id_field)
    _sanitize_scope(safe_fields)
    _sanitize_logger(safe_fields)
    for field, limit in TEXT_LIMITS.items():
        if field in safe_fields:
            safe_fields[field] = safe_text(safe_fields[field], fallback="unavailable", limit=limit)
    _sanitize_operation_fields(safe_fields)
    _sanitize_typed_fields(safe_fields)
    route_class = safe_fields.get("route_class")
    safe_fields["route_class"] = (
        route_class
        if isinstance(route_class, str) and route_class in ROUTE_CLASSES
        else "unmatched"
    )
    return safe_fields


def _sanitize_vocabularies(fields: dict[str, Any]) -> None:
    error_kind = fields.get("error_kind")
    if "error_kind" in fields and (
        not isinstance(error_kind, str) or error_kind not in ERROR_KINDS
    ):
        fields["error_kind"] = "unexpected"
    outcome = fields.get("outcome")
    if "outcome" in fields and (not isinstance(outcome, str) or outcome not in OUTCOMES):
        fields["outcome"] = "failed"
    if "reason" in fields:
        reason = safe_text(fields["reason"], fallback="runtime-other", limit=128).replace("_", "-")
        fields["reason"] = reason if reason in REASONS else "runtime-other"
    decision = fields.get("decision")
    if not isinstance(decision, str) or decision not in DECISIONS:
        fields.pop("decision", None)


def _sanitize_scope(fields: dict[str, Any]) -> None:
    if "scope" not in fields:
        return
    scope = safe_text(fields["scope"], fallback="", limit=65)
    if scope in SCOPE_VOCABULARY:
        fields["scope"] = scope
    else:
        fields.pop("scope")


def _sanitize_logger(fields: dict[str, Any]) -> None:
    if "logger" not in fields:
        return
    name = safe_text(fields["logger"], fallback="", limit=129)
    fields["logger"] = (
        name if LOGGER_PATTERN.fullmatch(name) else _opaque_text(fields["logger"], "logger")
    )


def _sanitize_operation_fields(fields: dict[str, Any]) -> None:
    if fields.get("operation") not in OPERATIONS:
        fields.pop("operation", None)
    for field in ("request_method", "upstream_method"):
        if field in fields:
            fields[field] = fields[field].upper()
            if fields[field] not in METHODS:
                fields.pop(field)


def _sanitize_typed_fields(fields: dict[str, Any]) -> None:
    for field in INTEGER_FIELDS | DURATION_FIELDS | BOOLEAN_FIELDS:
        if field not in fields:
            continue
        value = sanitize_output_field(field, fields[field])
        if value is None:
            fields.pop(field)
        else:
            fields[field] = value


def _sanitize_pattern_field(
    fields: dict[str, Any],
    key: str,
    pattern: re.Pattern[str],
    limit: int,
    *,
    fallback: str = "",
) -> None:
    if key not in fields:
        return
    candidate = safe_text(fields[key], fallback=fallback, limit=limit)
    if pattern.fullmatch(candidate):
        fields[key] = candidate
    else:
        fields.pop(key)


def _sanitize_identifier(fields: dict[str, Any], key: str, prefix: str) -> None:
    if key not in fields:
        return
    candidate = safe_text(fields[key], fallback="", limit=129)
    fields[key] = (
        candidate if WRITER_ID_PATTERN.fullmatch(candidate) else _opaque_text(fields[key], prefix)
    )
