from __future__ import annotations

from ipaddress import IPv4Address

import uvicorn

from .app import app as router_app
from .app import runtime
from .config import load_settings
from .logging import configure_logging
from .observability import RequestIdMiddleware

app = RequestIdMiddleware(router_app)


def main() -> None:
    configure_logging()
    settings = load_settings()
    runtime.configure(settings)
    bind_all_interfaces = str(IPv4Address(0))
    uvicorn.run(
        app,
        host=bind_all_interfaces,
        port=settings.memory_router_port,
        access_log=False,
        log_config=None,
        log_level="info",
    )


if __name__ == "__main__":
    main()
