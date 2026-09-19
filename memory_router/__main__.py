from __future__ import annotations

import logging

import uvicorn

from .app import app as router_app
from .app import runtime
from .config import load_settings
from .logging import configure_logging, log_event
from .observability import RequestIdMiddleware

app = RequestIdMiddleware(router_app)
logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    try:
        settings = load_settings()
    except RuntimeError as exc:
        log_event(
            logger,
            "error",
            "application_start_failed",
            operation="startup",
            error_kind="unexpected",
            error=exc,
            outcome="failed",
        )
        raise SystemExit(3) from None
    runtime.configure(settings)
    uvicorn.run(
        app,
        host=settings.memory_router_host,
        port=settings.memory_router_port,
        access_log=False,
        log_config=None,
        log_level="info",
    )


if __name__ == "__main__":
    main()
