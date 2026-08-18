from __future__ import annotations

import logging
import sys
import time
from collections.abc import MutableMapping
from typing import Any, Literal

import structlog

_SAFE_FIELDS = {
    "request_id",
    "operation",
    "upstream_method",
    "request_method",
    "error_kind",
    "upstream_status",
    "http_status",
    "outcome",
    "request_duration_ms",
    "operation_duration_ms",
    "route_class",
    "writer_id",
    "reason",
    "timeout_ms",
}
_OUTPUT_FIELDS = {"event", "level", "timestamp", "logger", *_SAFE_FIELDS}
_JSON_RENDERER = structlog.processors.JSONRenderer(sort_keys=True)
_LEVELS = {"info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}
_EVENTS = frozenset(
    {
        "application_started",
        "authentication_failed",
        "authentication_audit_failed",
        "bank_unavailable",
        "hindsight_readiness_failed",
        "hindsight_readiness_recovered",
        "hindsight_request_failed",
        "openclaw_security_audit_failed",
        "quarantine_placeholder_unavailable",
        "quarantine_sweeper_failed",
        "quarantine_write_unavailable",
        "recall_supplemental_audit_unavailable",
        "request_failed",
    }
)
_ERROR_KINDS = frozenset(
    {
        "timeout",
        "http",
        "invalid-response",
        "network",
        "response-too-large",
        "invalid_credentials",
        "unexpected",
    }
)
_OUTCOMES = frozenset({"failed", "degraded", "healthy", "unhealthy"})
_RESERVED = frozenset({"event", "level", "timestamp", "logger"})
_THROTTLED_EVENTS = _EVENTS - {
    "application_started",
    "authentication_failed",
    "authentication_audit_failed",
    "hindsight_readiness_failed",
    "hindsight_readiness_recovered",
    "quarantine_sweeper_failed",
}
_last_emitted: dict[tuple[str, str, str], float] = {}


def _drop_exception_data(_: logging.Logger, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    record = event_dict.get("_record")
    if isinstance(record, logging.LogRecord):
        record.exc_info = None
        record.stack_info = None
    for key in ("exc_info", "stack_info", "exception"):
        event_dict.pop(key, None)
    return event_dict


def _render_safe_json(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> str | bytes:
    """Render only the application log schema, including for foreign log records."""
    safe_event = {key: value for key, value in event_dict.items() if key in _OUTPUT_FIELDS}
    return _JSON_RENDERER(logger, method_name, safe_event)


def configure_logging() -> None:
    """Configure one-line JSON logs for Memory Router application loggers."""
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
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler._memory_router_json = True  # type: ignore[attr-defined]
    handler.setFormatter(formatter)
    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, "_memory_router_json", False):
            root.removeHandler(existing)
            existing.close()
    root.addHandler(handler)
    root.setLevel(min(root.level, logging.INFO) if root.level else logging.INFO)
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("uvicorn.error").disabled = False


def log_event(
    logger: logging.Logger,
    level: Literal["info", "warning", "error"],
    event: str,
    **fields: Any,
) -> None:
    """Emit only explicitly supplied structured fields through stdlib logging."""
    if event not in _EVENTS:
        raise ValueError("unregistered log event")
    if _RESERVED & fields.keys():
        raise ValueError("reserved structured log field")
    safe_fields = {
        key: value for key, value in fields.items() if key in _SAFE_FIELDS and value is not None
    }
    if "error_kind" in safe_fields and safe_fields["error_kind"] not in _ERROR_KINDS:
        safe_fields["error_kind"] = "unexpected"
    if "outcome" in safe_fields and safe_fields["outcome"] not in _OUTCOMES:
        safe_fields["outcome"] = "failed"
    if event in _THROTTLED_EVENTS:
        key = (
            event,
            str(safe_fields.get("route_class", "unmatched")),
            str(safe_fields.get("error_kind", "unexpected")),
        )
        now = time.monotonic()
        if now - _last_emitted.get(key, 0.0) < 60.0:
            return
        _last_emitted[key] = now
    logger.log(_LEVELS[level], event, extra=safe_fields)
