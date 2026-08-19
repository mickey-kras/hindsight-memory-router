from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
from collections.abc import MutableMapping
from types import TracebackType
from typing import Any, Literal

import structlog

from .logging_contract import (
    EVENTS,
    LEVELS,
    OUTPUT_FIELDS,
    RESERVED_FIELDS,
    THROTTLED_EVENTS,
    safe_text,
    sanitize_fields,
    sanitize_output_field,
)

_JSON_RENDERER = structlog.processors.JSONRenderer(sort_keys=True)
_MEMORY_ROUTER_EVENT = object()
LOG_THROTTLE_INTERVAL_SECONDS = 60.0
_last_emitted: dict[tuple[str, str, str], float] = {}
_suppressed: dict[tuple[str, str, str], int] = {}


def event_catalog() -> frozenset[str]:
    return EVENTS


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
        frame = sys._getframe(3)  # noqa: SLF001 - bounded call-site diagnostic
        source = f"{logger.name}:{frame.f_code.co_name}:{frame.f_lineno}"
    except (AttributeError, ValueError):
        source = "memory_router:unknown-caller"
    return _site_fingerprint(source)


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
    message = safe_text(event_dict.get("event", ""), fallback="", limit=512).strip()
    logger_name = safe_text(event_dict.get("logger", ""), fallback="", limit=128)
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


def _render_safe_json(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> str | bytes:
    """Render only the application log schema, including for foreign log records."""
    safe_event = {
        key: sanitized
        for key, value in event_dict.items()
        if key in OUTPUT_FIELDS and (sanitized := sanitize_output_field(key, value)) is not None
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
    event, level, safe_fields = _prepare_event(logger, event, level, fields)
    if not _admit_event(event, safe_fields):
        return
    if isinstance(error, BaseException):
        safe_fields["error_fingerprint"] = error_fingerprint(error)
    safe_fields["_memory_router_event"] = _MEMORY_ROUTER_EVENT
    numeric_level = LEVELS.get(level, logging.ERROR) if isinstance(level, str) else logging.ERROR
    logger.log(numeric_level, event, extra=safe_fields, stacklevel=2)


def _prepare_event(
    logger: logging.Logger,
    event: str,
    level: Literal["info", "warning", "error"],
    fields: dict[str, Any],
) -> tuple[str, Literal["info", "warning", "error"], dict[str, Any]]:
    contract_reason: str | None = None
    if not isinstance(event, str) or event not in EVENTS:
        event = "logging_contract_violation"
        contract_reason = "unregistered-event"
    if RESERVED_FIELDS & fields.keys():
        fields = {key: value for key, value in fields.items() if key not in RESERVED_FIELDS}
        event = "logging_contract_violation"
        contract_reason = "reserved-field"
    if contract_reason is not None:
        fields["reason"] = contract_reason
        fields["error_fingerprint"] = _caller_fingerprint(logger)
        level = "error"
    return event, level, sanitize_fields(fields)


def _admit_event(event: str, fields: dict[str, Any]) -> bool:
    if event not in THROTTLED_EVENTS:
        return True
    key = (
        event,
        fields["route_class"],
        safe_text(fields.get("error_kind", "unexpected"), fallback="unexpected", limit=32),
    )
    now = time.monotonic()
    last_emitted = _last_emitted.get(key)
    if last_emitted is not None and now - last_emitted < LOG_THROTTLE_INTERVAL_SECONDS:
        _suppressed[key] = _suppressed.get(key, 0) + 1
        return False
    _last_emitted[key] = now
    suppressed = _suppressed.pop(key, 0)
    if suppressed:
        fields["suppressed"] = suppressed
    return True
