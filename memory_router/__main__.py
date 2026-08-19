from __future__ import annotations

from ipaddress import IPv4Address

import uvicorn

from .app import app as router_app
from .config import integer_env
from .logging import configure_logging
from .observability import RequestIdMiddleware

app = RequestIdMiddleware(router_app)


def main() -> None:
    configure_logging()
    port = integer_env("MEMORY_ROUTER_PORT", 8890, minimum=1)
    bind_all_interfaces = str(IPv4Address(0))
    uvicorn.run(
        app,
        host=bind_all_interfaces,
        port=port,
        access_log=False,
        log_config=None,
        log_level="info",
    )


if __name__ == "__main__":
    main()
