from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from .errors import HttpError


@dataclass(frozen=True, slots=True)
class HindsightLimitConfig:
    retain_writer_max: int = 30
    retain_global_max: int = 300
    recall_writer_max: int = 120
    recall_global_max: int = 1200
    rate_limit_window_ms: int = 60_000
    max_retain_items: int = 100
    max_retain_content_bytes: int = 524_288
    max_recall_query_bytes: int = 32_768
    max_recall_max_tokens: int = 8192


class InMemorySlidingWindow:
    def __init__(self) -> None:
        self._events: dict[str, deque[int]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def consume_many(
        self, buckets: list[tuple[str, int, int]], at_ms: int | None = None
    ) -> None:
        now = at_ms if at_ms is not None else int(time.time() * 1000)
        async with self._lock:
            normalized: list[deque[int]] = []
            for key, maximum, window_ms in buckets:
                if maximum <= 0 or window_ms <= 0:
                    continue
                queue = self._events[key]
                cutoff = now - window_ms
                while queue and queue[0] <= cutoff:
                    queue.popleft()
                if len(queue) >= maximum:
                    raise HttpError(429, "quarantine_rate_limited", "too many quarantine writes")
                normalized.append(queue)
            for queue in normalized:
                queue.append(now)


class HindsightLimits:
    def __init__(self, config: HindsightLimitConfig, limiter: Any) -> None:
        self.config = config
        self.limiter = limiter

    def assert_retain_bounds(self, body: dict[str, Any]) -> None:
        if len(body["items"]) > self.config.max_retain_items:
            raise HttpError(
                413, "retain_item_limit_exceeded", "retain request contains too many memory items"
            )
        if _string_value_bytes(body) > self.config.max_retain_content_bytes:
            raise HttpError(
                413, "retain_content_too_large", "retain content exceeds the configured byte limit"
            )

    def assert_recall_bounds(self, body: dict[str, Any]) -> None:
        if len(body["query"].encode()) > self.config.max_recall_query_bytes:
            raise HttpError(
                413, "recall_query_too_large", "recall query exceeds the configured byte limit"
            )
        if (
            body.get("max_tokens") is not None
            and body["max_tokens"] > self.config.max_recall_max_tokens
        ):
            raise HttpError(
                413, "recall_max_tokens_exceeded", "recall max_tokens exceeds the configured limit"
            )

    async def consume_retain(self, writer_id: str) -> None:
        await self._consume(
            "retain", writer_id, self.config.retain_writer_max, self.config.retain_global_max
        )

    async def consume_recall(self, writer_id: str) -> None:
        await self._consume(
            "recall", writer_id, self.config.recall_writer_max, self.config.recall_global_max
        )

    async def _consume(self, kind: str, writer_id: str, writer_max: int, global_max: int) -> None:
        try:
            await self.limiter.consume_many(
                [
                    (
                        f"hindsight:{kind}:writer:{writer_id}",
                        writer_max,
                        self.config.rate_limit_window_ms,
                    ),
                    (f"hindsight:{kind}:global", global_max, self.config.rate_limit_window_ms),
                ]
            )
        except HttpError as exc:
            if exc.status != 429:
                raise
            retry_after = max(1, (self.config.rate_limit_window_ms + 999) // 1000)
            raise HttpError(
                429,
                "hindsight_rate_limited",
                f"too many Hindsight {kind} requests",
                {"retry-after": str(retry_after)},
            ) from exc


def _string_value_bytes(value: Any) -> int:
    total = 0
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            total += len(current.encode())
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, dict):
            pending.extend(current.values())
    return total
