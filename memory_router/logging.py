from __future__ import annotations

import hashlib
import logging
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
_LEVELS = {"info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}
_EVENTS = frozenset(
    {
        "application_start_failed",
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
_REASONS = frozenset(
    {
        "admin-cleanup-token-missing",
        "admin-read-token-missing",
        "admin-review-token-missing",
        "anonymous-mode",
        "application-shutdown",
        "application-startup",
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
_MAX_WRITER_ID_LENGTH = 128
_FINGERPRINT_PATTERN = re.compile(r"^(?:[A-Za-z][A-Za-z0-9.]{0,63}|site:[0-9a-f]{16})$")
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
        source = f"{traceback.tb_frame.f_globals.get('__name__', '')}:{code.co_name}:{traceback.tb_lineno}"
    return _site_fingerprint(source)


def _site_fingerprint(source: str) -> str:
    return f"site:{hashlib.sha256(source.encode()).hexdigest()[:16]}"


def _caller_fingerprint(logger: logging.Logger) -> str:
    frame = sys._getframe(2)  # noqa: SLF001 - bounded call-site diagnostic
    source = f"{logger.name}:{frame.f_code.co_name}:{frame.f_lineno}"
    return _site_fingerprint(source)


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
    if event_dict.get("_from_structlog"):
        return event_dict
    if event_dict.get("_memory_router_event") is True:
        return event_dict
    message = str(event_dict.get("event", "")).strip()
    if str(event_dict.get("logger", "")).startswith("memory_router"):
        record = event_dict.get("_record")
        source = "memory_router:unknown:0"
        if isinstance(record, logging.LogRecord):
            source = f"{record.name}:{record.funcName}:{record.lineno}"
        event_dict["event"] = "logging_contract_violation"
        event_dict["reason"] = "direct-stdlib-log"
        event_dict["error_fingerprint"] = _site_fingerprint(source)
        return event_dict
    lowered = message.lower()
    reason = "runtime-other"
    if "invalid http request" in lowered:
        reason = "http-protocol-error"
    elif "started server process" in lowered:
        reason = "server-started"
    elif "application startup" in lowered:
        reason = "application-startup"
    elif "shutting down" in lowered:
        reason = "server-stopping"
    elif "application shutdown" in lowered:
        reason = "application-shutdown"
    elif "finished server process" in lowered:
        reason = "server-finished"
    event_dict["event"] = "runtime_message"
    event_dict["reason"] = reason
    return event_dict


def _render_safe_json(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> str | bytes:
    """Render only the application log schema, including for foreign log records."""
    safe_event = {key: value for key, value in event_dict.items() if key in _OUTPUT_FIELDS}
    return _JSON_RENDERER(logger, method_name, safe_event)


class _ProtocolNoiseFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.last: float | None = None
        self.suppressed = 0

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        noisy = any(
            value in message
            for value in (
                "Invalid HTTP request",
                "Unsupported upgrade request",
                "No supported WebSocket library was found",
            )
        )
        if record.levelno < logging.WARNING or not noisy:
            return True
        now = time.monotonic()
        if self.last is not None and now - self.last < LOG_THROTTLE_INTERVAL_SECONDS:
            self.suppressed += 1
            return False
        if self.suppressed:
            record.suppressed = self.suppressed
            self.suppressed = 0
        self.last = now
        return True


def _json_handler(*, filter_protocol_noise: bool = False) -> logging.Handler:
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
    if filter_protocol_noise:
        handler.addFilter(_ProtocolNoiseFilter())
    return handler


def _replace_owned_handler(logger: logging.Logger, handler: logging.Handler) -> None:
    for existing in list(logger.handlers):
        if getattr(existing, "_memory_router_json", False):
            logger.removeHandler(existing)
            existing.close()
    logger.addHandler(handler)


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
        _replace_owned_handler(uvicorn_error, _json_handler(filter_protocol_noise=True))
        uvicorn_error.propagate = False
    uvicorn_error.disabled = False
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    logging.lastResort = _json_handler()
    logging.lastResort.setLevel(logging.WARNING)


def log_event(
    logger: logging.Logger,
    level: Literal["info", "warning", "error"],
    event: str,
    *,
    error: BaseException | None = None,
    **fields: Any,
) -> None:
    """Emit a bounded event; contract mistakes never mask the original failure."""
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
    if "error_fingerprint" in safe_fields and not _FINGERPRINT_PATTERN.fullmatch(
        str(safe_fields["error_fingerprint"])
    ):
        safe_fields.pop("error_fingerprint")
    if "outcome" in safe_fields and (
        not isinstance(safe_fields["outcome"], str) or safe_fields["outcome"] not in _OUTCOMES
    ):
        safe_fields["outcome"] = "failed"
    if "reason" in safe_fields:
        normalized_reason = str(safe_fields["reason"]).replace("_", "-")
        safe_fields["reason"] = (
            normalized_reason if normalized_reason in _REASONS else "runtime-other"
        )
    if "writer_id" in safe_fields:
        safe_fields["writer_id"] = str(safe_fields["writer_id"])[:_MAX_WRITER_ID_LENGTH]
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
            str(safe_fields.get("error_kind", "unexpected")),
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
    if error is not None:
        safe_fields["error_fingerprint"] = error_fingerprint(error)
    safe_fields["_memory_router_event"] = True
    numeric_level = _LEVELS.get(level, logging.ERROR) if isinstance(level, str) else logging.ERROR
    logger.log(numeric_level, event, extra=safe_fields, stacklevel=2)
