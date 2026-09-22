from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from contextlib import suppress


async def finish_before_cancelling[T](operation: Awaitable[T]) -> T:
    task = asyncio.ensure_future(operation)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError as error:
        while not task.done():
            with suppress(asyncio.CancelledError):
                await asyncio.wait({task})
        if not task.cancelled():
            error.__cause__ = task.exception()
        raise


async def cleanup_result(operation: Awaitable[None]) -> BaseException | None:
    cleanup = asyncio.gather(operation, return_exceptions=True)
    with suppress(asyncio.CancelledError):
        await finish_before_cancelling(cleanup)
    (result,) = cleanup.result()
    return result if isinstance(result, BaseException) else None
