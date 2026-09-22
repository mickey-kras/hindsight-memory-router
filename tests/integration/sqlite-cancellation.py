from __future__ import annotations

import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

from memory_router.db import create_database


async def verify_cancellation(path: Path) -> None:
    database = await create_database(f"sqlite:{path}")
    inserted = asyncio.Event()

    async def insert() -> None:
        async with database.transaction() as tx:
            await tx.execute(
                "INSERT INTO quarantine_events VALUES (?, ?, ?, ?, ?)",
                ("cancelled", "probe", "now", "probe", "{}"),
            )
            inserted.set()
            await asyncio.Event().wait()

    transaction = asyncio.create_task(insert())
    try:
        await asyncio.wait_for(inserted.wait(), timeout=5)
        transaction.cancel()
        try:
            await asyncio.wait_for(transaction, timeout=5)
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("transaction cancellation was swallowed")
        await database.ping()
        async with database.transaction() as tx:
            assert await tx.fetchall("SELECT * FROM quarantine_events") == []
    finally:
        transaction.cancel()
        await asyncio.gather(transaction, return_exceptions=True)
        await database.close()


with TemporaryDirectory() as directory:
    asyncio.run(verify_cancellation(Path(directory) / "quarantine.db"))
