from __future__ import annotations

import uvicorn

from .app import create_app
from .config import Settings

app = create_app()


def main() -> None:
    settings = Settings.from_env()
    uvicorn.run(
        "memory_router.main:app",
        host="0.0.0.0",
        port=settings.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()
