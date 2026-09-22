from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from tempfile import TemporaryDirectory

from memory_router.app import Runtime
from memory_router.config import load_settings


async def verify_startup_cleanup(path: Path) -> None:
    settings = load_settings(quarantine_database_url=f"sqlite:{path}")
    runtime = Runtime(settings.model_copy(update={"quarantine_public_key": "invalid"}))
    initial_threads = set(threading.enumerate())
    for _ in range(2):
        try:
            await runtime.start()
        except ValueError:
            pass
        else:
            raise AssertionError("invalid public key started successfully")
        for worker in set(threading.enumerate()) - initial_threads:
            worker.join(timeout=1)
            assert not worker.is_alive(), "failed startup left a live worker"

    runtime.configure(settings)
    await runtime.start()
    try:
        assert runtime.repository is not None
        await runtime.repository.ping()
    finally:
        await runtime.stop()
    for worker in set(threading.enumerate()) - initial_threads:
        worker.join(timeout=1)
        assert not worker.is_alive(), "shutdown left a live worker"


with TemporaryDirectory() as directory:
    asyncio.run(verify_startup_cleanup(Path(directory) / "quarantine.db"))
