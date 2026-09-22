from __future__ import annotations

import asyncio
from collections.abc import Awaitable


async def finish_before_cancelling[T](operation: Awaitable[T]) -> T:
    task = asyncio.ensure_future(operation)
    cancelled: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            cancelled = cancelled or error
        except BaseException:
            break
    if cancelled is not None:
        try:
            task.result()
        except BaseException as error:
            raise cancelled from error
        raise cancelled
    return task.result()
