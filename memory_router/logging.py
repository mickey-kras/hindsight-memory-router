from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import sys
import time
from collections.abc import MutableMapping
from types import TracebackType
from typing import Any, Literal

import structlog

_SAFE_FIELDS = {
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
    "reason",
    "timeout_ms",
    "suppressed",
}
_OUTPUT_FIELDS = {"event", "level", "timestamp", "logger", *_SAFE_FIELDS}
_JSON_RENDERER = structlog.processors.JSONRenderer(sort_keys=True)
_MEMORY_ROUTER_EVENT = object()
_LEVELS = {"info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}
_EVENTS = frozenset(
    {
        "application_start_failed",
        "application_stop_failed",
        "application_started",
        "authentication_failed",
        "authentication_audit_failed",
        "bank_unavailable",
        "configuration_warning",
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
_ERROR_KINDS = frozenset(
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
        "timeout",
        "unexpected",
    }
)
_OUTCOMES = frozenset({"failed", "degraded", "healthy", "unhealthy"})
_ROUTE_CLASSES = frozenset(
    {"readiness", "liveness", "version", "admin", "memory", "openclaw", "unmatched"}
)
_OPERATIONS = frozenset(
    {
        "authenticate",
        "configuration",
        "health",
        "invalidate_memory",
        "openclaw_bank",
        "openclaw_config",
        "openclaw_mental-models",
        "openclaw_reflect",
        "quarantine_maintenance",
        "recall",
        "request",
        "retain",
        "security_audit",
        "shutdown",
        "startup",
        "storage_health",
        "version",
    }
)
_METHODS = frozenset({"GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS"})
_REASONS = frozenset(
    {
        "admin-cleanup-token-missing",
        "admin-read-token-missing",
        "admin-review-token-missing",
        "anonymous-mode",
        "application-shutdown",
        "application-startup",
        "asgi-application-error",
        "http-protocol-error",
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
_RESERVED = frozenset({"event", "level", "timestamp", "logger"})
_THROTTLED_EVENTS = _EVENTS - {
    "application_start_failed",
    "application_started",
    "configuration_warning",
    "hindsight_readiness_failed",
    "logging_contract_violation",
    "runtime_message",
    "storage_readiness_failed",
}
_TEXT_LIMITS = {
    "request_id": 128,
    "operation": 64,
    "upstream_method": 16,
    "request_method": 16,
    "writer_id": 128,
    "logger": 128,
    "level": 16,
    "timestamp": 64,
    "event": 64,
}
_INTEGER_FIELDS = {"upstream_status", "http_status", "timeout_ms", "suppressed"}
_DURATION_FIELDS = {"request_duration_ms", "operation_duration_ms"}
_FINGERPRINT_PATTERN = re.compile(r"^(?:[A-Za-z][A-Za-z0-9.]{0,63}|site:[0-9a-f]{16})$")
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
LOG_THROTTLE_INTERVAL_SECONDS = 60.0
_last_emitted: dict[tuple[str, str, str], float] = {}
_suppressed: dict[tuple[str, str, str], int] = {}


def event_catalog() -> frozenset[str]:
    return _EVENTS


def reset_log_state() -> None:
    _last_emitted.clear()
    _suppressed.clear()


def error_fingerprint(exc: BaseException) -> str:
    """Return a bounded diagnostic without exception text or local paths."""
    safe_classes = {
        "AssertionError",
        "ConnectionError",
        "OSError",
        "RuntimeError",
        "TimeoutError",
        "TypeError",
        "ValueError",
    }
    try:
        name = type(exc).__name__
        if name in safe_classes:
            return name
        traceback: TracebackType | None = exc.__traceback__
        if traceback is None:
            source = f"{type(exc).__module__}.{name}"
        else:
            while traceback.tb_next is not None:
                traceback = traceback.tb_next
            code = traceback.tb_frame.f_code
            source = (
                f"{traceback.tb_frame.f_globals.get('__name__', '')}:"
                f"{code.co_name}:{traceback.tb_lineno}"
            )
        return _site_fingerprint(source)
    except Exception:
        return _site_fingerprint("memory_router:error-fingerprint")


def _site_fingerprint(source: str) -> str:
    return f"site:{hashlib.sha256(source.encode(errors='replace')).hexdigest()[:16]}"


def _caller_fingerprint(logger: logging.Logger) -> str:
    try:
        frame = sys._getframe(2)  # noqa: SLF001 - bounded call-site diagnostic
        source = f"{logger.name}:{frame.f_code.co_name}:{frame.f_lineno}"
    except (AttributeError, ValueError):
        source = "memory_router:unknown-caller"
    return _site_fingerprint(source)


def _safe_text(value: Any, *, fallback: str, limit: int) -> str:
    try:
        return str(value)[:limit]
    except Exception:
        return fallback


def _runtime_reason(message: str) -> str:
    lowered = message.lower()
    if (
        "invalid http request" in lowered
        or "unsupported upgrade request" in lowered
        or "no supported websocket library" in lowered
    ):
        return "http-protocol-error"
    if "exception in asgi application" in lowered:
        return "asgi-application-error"
    if "started server process" in lowered:
        return "server-started"
    if "uvicorn running on" in lowered:
        return "server-running"
    if "application startup" in lowered:
        return "application-startup"
    if "shutting down" in lowered:
        return "server-stopping"
    if "application shutdown" in lowered:
        return "application-shutdown"
    if "finished server process" in lowered:
        return "server-finished"
    return "runtime-other"


def _drop_exception_data(_: logging.Logger, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    record = event_dict.get("_record")
    if isinstance(record, logging.LogRecord):
        record.exc_info = None
        record.stack_info = None
    for key in ("exc_info", "stack_info", "exception"):
        event_dict.pop(key, None)
    return event_dict


def _normalize_foreign_event(
    _: logging.Logger, __: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    if event_dict.get("_memory_router_event") is _MEMORY_ROUTER_EVENT:
        return event_dict
    message = _safe_text(event_dict.get("event", ""), fallback="", limit=512).strip()
    logger_name = _safe_text(event_dict.get("logger", ""), fallback="", limit=128)
    normalized: dict[str, Any] = {
        key: event_dict[key]
        for key in ("_record", "_from_structlog", "level", "logger", "timestamp")
        if key in event_dict
    }
    if logger_name.startswith("memory_router"):
        record = event_dict.get("_record")
        source = "memory_router:unknown:0"
        if isinstance(record, logging.LogRecord):
            source = f"{record.name}:{record.funcName}:{record.lineno}"
        normalized.update(
            event="logging_contract_violation",
            reason="direct-stdlib-log",
            error_fingerprint=_site_fingerprint(source),
        )
        return normalized
    normalized.update(event="runtime_message", reason=_runtime_reason(message))
    suppressed = event_dict.get("suppressed")
    if isinstance(suppressed, int) and not isinstance(suppressed, bool) and suppressed > 0:
        normalized["suppressed"] = suppressed
    return normalized


def _sanitize_output_field(key: str, value: Any) -> Any | None:
    if key in _TEXT_LIMITS:
        return _safe_text(value, fallback="unavailable", limit=_TEXT_LIMITS[key])
    if key in _INTEGER_FIELDS:
        return (
            value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
        )
    if key in _DURATION_FIELDS:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            numeric = float(value)
            return numeric if math.isfinite(numeric) and numeric >= 0 else None
        return None
    if key in {"error_kind", "error_fingerprint", "outcome", "route_class", "reason"}:
        return _safe_text(value, fallback="unavailable", limit=128)
    return None


def _render_safe_json(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> str | bytes:
    """Render only the application log schema, including for foreign log records."""
    safe_event = {
        key: sanitized
        for key, value in event_dict.items()
        if key in _OUTPUT_FIELDS and (sanitized := _sanitize_output_field(key, value)) is not None
    }
    try:
        return _JSON_RENDERER(logger, method_name, safe_event)
    except Exception:
        return json.dumps(
            {
                "event": "logging_contract_violation",
                "level": "error",
                "logger": "memory_router.logging",
                "reason": "runtime-other",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            sort_keys=True,
            separators=(",", ":"),
        )


class _ProtocolNoiseFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.last_by_reason: dict[str, float] = {}
        self.suppressed_by_reason: dict[str, int] = {}

    @property
    def last(self) -> float | None:
        return self.last_by_reason.get("http-protocol-error")

    @last.setter
    def last(self, value: float | None) -> None:
        if value is None:
            self.last_by_reason.pop("http-protocol-error", None)
        else:
            self.last_by_reason["http-protocol-error"] = value

    @property
    def suppressed(self) -> int:
        return self.suppressed_by_reason.get("http-protocol-error", 0)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return False
        reason = _runtime_reason(message)
        if record.levelno < logging.WARNING or reason not in {
            "http-protocol-error",
            "asgi-application-error",
            "runtime-other",
        }:
            return True
        now = time.monotonic()
        last = self.last_by_reason.get(reason)
        if last is not None and now - last < LOG_THROTTLE_INTERVAL_SECONDS:
            self.suppressed_by_reason[reason] = self.suppressed_by_reason.get(reason, 0) + 1
            return False
        suppressed = self.suppressed_by_reason.pop(reason, 0)
        if suppressed:
            record.suppressed = suppressed
        self.last_by_reason[reason] = now
        return True


class _SafeRecordFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.getMessage()
        except Exception:
            return False
        return True


def _json_handler(*, filter_runtime_noise: bool = False) -> logging.Handler:
    shared_processors: list[Any] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _drop_exception_data,
    ]
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=_render_safe_json,
        foreign_pre_chain=[
            structlog.stdlib.ExtraAdder(),
            *shared_processors,
            _normalize_foreign_event,
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler._memory_router_json = True  # type: ignore[attr-defined]
    handler.setFormatter(formatter)
    handler.addFilter(_SafeRecordFilter())
    if filter_runtime_noise:
        handler.addFilter(_ProtocolNoiseFilter())
    return handler


def _replace_owned_handler(logger: logging.Logger, handler: logging.Handler) -> None:
    for existing in list(logger.handlers):
        if getattr(existing, "_memory_router_json", False):
            logger.removeHandler(existing)
            existing.close()
    logger.addHandler(handler)


def _replace_owned_noise_filter(logger: logging.Logger) -> None:
    for existing in list(logger.filters):
        if getattr(existing, "_memory_router_runtime_noise", False):
            logger.removeFilter(existing)
    noise_filter = _ProtocolNoiseFilter()
    noise_filter._memory_router_runtime_noise = True  # type: ignore[attr-defined]
    logger.addFilter(noise_filter)


def configure_logging() -> None:
    """Configure scoped one-line JSON logs without mutating the deployer's root logger."""
    application_logger = logging.getLogger("memory_router")
    _replace_owned_handler(application_logger, _json_handler())
    application_logger.setLevel(logging.INFO)
    application_logger.propagate = False

    uvicorn_error = logging.getLogger("uvicorn.error")
    if not uvicorn_error.handlers or any(
        getattr(handler, "_memory_router_json", False) for handler in uvicorn_error.handlers
    ):
        _replace_owned_handler(uvicorn_error, _json_handler())
        uvicorn_error.propagate = False
    _replace_owned_noise_filter(uvicorn_error)
    uvicorn_error.disabled = False
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    logging.lastResort = _json_handler(filter_runtime_noise=True)
    logging.lastResort.setLevel(logging.WARNING)


def log_event(
    logger: logging.Logger,
    level: Literal["info", "warning", "error"],
    event: str,
    *,
    error: Any = None,
    **fields: Any,
) -> None:
    """Emit a bounded event; contract mistakes never mask the original failure."""
    try:
        _log_event(logger, level, event, error=error, **fields)
    except Exception:
        return


def _log_event(
    logger: logging.Logger,
    level: Literal["info", "warning", "error"],
    event: str,
    *,
    error: Any = None,
    **fields: Any,
) -> None:
    contract_reason: str | None = None
    if not isinstance(event, str) or event not in _EVENTS:
        event = "logging_contract_violation"
        contract_reason = "unregistered-event"
    if _RESERVED & fields.keys():
        fields = {key: value for key, value in fields.items() if key not in _RESERVED}
        event = "logging_contract_violation"
        contract_reason = "reserved-field"
    safe_fields = {
        key: value for key, value in fields.items() if key in _SAFE_FIELDS and value is not None
    }
    if contract_reason is not None:
        safe_fields["reason"] = contract_reason
        safe_fields["error_fingerprint"] = _caller_fingerprint(logger)
        level = "error"
    if "error_kind" in safe_fields and (
        not isinstance(safe_fields["error_kind"], str)
        or safe_fields["error_kind"] not in _ERROR_KINDS
    ):
        safe_fields["error_kind"] = "unexpected"
    if "error_fingerprint" in safe_fields:
        fingerprint = _safe_text(safe_fields["error_fingerprint"], fallback="", limit=80)
        if _FINGERPRINT_PATTERN.fullmatch(fingerprint):
            safe_fields["error_fingerprint"] = fingerprint
        else:
            safe_fields.pop("error_fingerprint")
    if "outcome" in safe_fields and (
        not isinstance(safe_fields["outcome"], str) or safe_fields["outcome"] not in _OUTCOMES
    ):
        safe_fields["outcome"] = "failed"
    if "reason" in safe_fields:
        normalized_reason = _safe_text(
            safe_fields["reason"], fallback="runtime-other", limit=128
        ).replace("_", "-")
        safe_fields["reason"] = (
            normalized_reason if normalized_reason in _REASONS else "runtime-other"
        )
    for field, limit in _TEXT_LIMITS.items():
        if field in safe_fields:
            safe_fields[field] = _safe_text(safe_fields[field], fallback="unavailable", limit=limit)
    if safe_fields.get("operation") not in _OPERATIONS:
        safe_fields.pop("operation", None)
    for field in ("request_method", "upstream_method"):
        if field in safe_fields:
            method = safe_fields[field].upper()
            if method in _METHODS:
                safe_fields[field] = method
            else:
                safe_fields.pop(field)
    if "request_id" in safe_fields and not _REQUEST_ID_PATTERN.fullmatch(safe_fields["request_id"]):
        safe_fields.pop("request_id")
    for field in _INTEGER_FIELDS:
        if field in safe_fields and _sanitize_output_field(field, safe_fields[field]) is None:
            safe_fields.pop(field)
    for field in _DURATION_FIELDS:
        if field in safe_fields:
            sanitized = _sanitize_output_field(field, safe_fields[field])
            if sanitized is None:
                safe_fields.pop(field)
            else:
                safe_fields[field] = sanitized
    route_class = safe_fields.get("route_class")
    safe_fields["route_class"] = (
        route_class
        if isinstance(route_class, str) and route_class in _ROUTE_CLASSES
        else "unmatched"
    )
    if event in _THROTTLED_EVENTS:
        key = (
            event,
            safe_fields["route_class"],
            _safe_text(
                safe_fields.get("error_kind", "unexpected"), fallback="unexpected", limit=32
            ),
        )
        now = time.monotonic()
        last_emitted = _last_emitted.get(key)
        if last_emitted is not None and now - last_emitted < LOG_THROTTLE_INTERVAL_SECONDS:
            _suppressed[key] = _suppressed.get(key, 0) + 1
            return
        _last_emitted[key] = now
        suppressed = _suppressed.pop(key, 0)
        if suppressed:
            safe_fields["suppressed"] = suppressed
    if isinstance(error, BaseException):
        safe_fields["error_fingerprint"] = error_fingerprint(error)
    safe_fields["_memory_router_event"] = _MEMORY_ROUTER_EVENT
    numeric_level = _LEVELS.get(level, logging.ERROR) if isinstance(level, str) else logging.ERROR
    logger.log(numeric_level, event, extra=safe_fields, stacklevel=2)
