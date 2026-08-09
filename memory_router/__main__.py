from __future__ import annotations

from ipaddress import IPv4Address

import uvicorn

from .app import app as router_app
from .config import integer_env
from .observability import RequestIdMiddleware

app = RequestIdMiddleware(router_app)


def main() -> None:
    port = integer_env("MEMORY_ROUTER_PORT", 8890, minimum=1)
    bind_all_interfaces = str(IPv4Address(0))
    uvicorn.run(
        app,
        host=bind_all_interfaces,
        port=port,
        access_log=False,
    )


if __name__ == "__main__":
    main()
