from __future__ import annotations

import logging
import sys
from typing import Any, Literal

import structlog

_SAFE_FIELDS = {
    "request_id",
    "operation",
    "method",
    "error_kind",
    "upstream_status",
    "status",
    "duration_ms",
    "route_class",
}
_OUTPUT_FIELDS = {"event", "level", "timestamp", *_SAFE_FIELDS}
_JSON_RENDERER = structlog.processors.JSONRenderer(sort_keys=True)


class _ApplicationLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name == "memory_router" or record.name.startswith("memory_router.")


def _drop_exception_data(_: logging.Logger, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    record = event_dict.get("_record")
    if isinstance(record, logging.LogRecord):
        record.exc_info = None
        record.stack_info = None
    for key in ("exc_info", "stack_info", "exception"):
        event_dict.pop(key, None)
    return event_dict


def _render_safe_json(logger: logging.Logger, method_name: str, event_dict: dict[str, Any]) -> str:
    """Render only the application log schema, including for foreign log records."""
    safe_event = {key: value for key, value in event_dict.items() if key in _OUTPUT_FIELDS}
    return _JSON_RENDERER(logger, method_name, safe_event)


def configure_logging() -> None:
    """Configure one-line JSON logs for Memory Router application loggers."""
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
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
    handler.addFilter(_ApplicationLogFilter())
    handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("uvicorn.error").disabled = True
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def log_event(
    logger: logging.Logger,
    level: Literal["warning", "error"],
    event: str,
    **fields: Any,
) -> None:
    """Emit only explicitly supplied structured fields through stdlib logging."""
    safe_fields = {
        key: value for key, value in fields.items() if key in _SAFE_FIELDS and value is not None
    }
    getattr(logger, level)(event, extra=safe_fields)
