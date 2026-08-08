from __future__ import annotations

import uvicorn

from .config import integer_env


def main() -> None:
    port = integer_env("MEMORY_ROUTER_PORT", 8890, minimum=1)
    uvicorn.run("memory_router.app:app", host="0.0.0.0", port=port, access_log=False)


if __name__ == "__main__":
    main()
