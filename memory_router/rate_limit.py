from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from .errors import HttpError

T = TypeVar("T")
Bucket = tuple[str, int, int]
Distinct = tuple[str, str, int, int]


def rate_limited() -> HttpError:
    return HttpError(429, "quarantine_rate_limited", "too many quarantine writes")


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self.events: dict[str, deque[int]] = defaultdict(deque)
        self.distinct: dict[str, dict[str, int]] = defaultdict(dict)
        self.locks: dict[str, asyncio.Lock] = {}
        self.guard = asyncio.Lock()

    async def consume_many(self, buckets: list[Bucket], at_ms: int | None = None) -> None:
        await self.consume_many_distinct(buckets, [], at_ms)

    async def consume_many_distinct(
        self, buckets: list[Bucket], identities: list[Distinct], at_ms: int | None = None
    ) -> None:
        now = at_ms if at_ms is not None else int(time.time() * 1000)
        async with self.guard:
            live: list[deque[int]] = []
            for key, maximum, window in buckets:
                if maximum <= 0 or window <= 0:
                    continue
                queue = self.events[key]
                cutoff = now - window
                while queue and queue[0] <= cutoff:
                    queue.popleft()
                if len(queue) >= maximum:
                    raise rate_limited()
                live.append(queue)
            additions: dict[str, set[str]] = defaultdict(set)
            for scope, identity, maximum, window in identities:
                if maximum <= 0 or window <= 0:
                    continue
                cutoff = now - window
                current = self.distinct[scope]
                for key, timestamp in list(current.items()):
                    if timestamp <= cutoff:
                        del current[key]
                if identity not in current:
                    additions[scope].add(identity)
            for scope, _, maximum, _ in identities:
                if maximum > 0 and len(self.distinct[scope]) + len(additions[scope]) > maximum:
                    raise rate_limited()
            for queue in live:
                queue.append(now)
            for scope, identity, maximum, window in identities:
                if maximum > 0 and window > 0:
                    self.distinct[scope][identity] = now

    async def with_identity_lock(
        self, identity: str, operation: Callable[[InMemoryRateLimiter], Awaitable[T]]
    ) -> T:
        async with self.guard:
            lock = self.locks.setdefault(identity, asyncio.Lock())
        async with lock:
            return await operation(self)


class _PostgresSession:
    def __init__(self, tx: Any) -> None:
        self.tx = tx

    async def consume_many(self, buckets: list[Bucket], at_ms: int | None = None) -> None:
        await self.consume_many_distinct(buckets, [], at_ms)

    async def consume_many_distinct(
        self, buckets: list[Bucket], identities: list[Distinct], at_ms: int | None = None
    ) -> None:
        normalized_buckets = sorted(
            {
                key: (key, maximum, window)
                for key, maximum, window in buckets
                if maximum > 0 and window > 0
            }.values()
        )
        normalized_identities = sorted(
            {
                (scope, identity): (scope, identity, maximum, window)
                for scope, identity, maximum, window in identities
                if maximum > 0 and window > 0
            }.values()
        )
        if not normalized_buckets and not normalized_identities:
            return
        for key in sorted(
            {f"rate-limit:{key}" for key, _, _ in normalized_buckets}
            | {f"rate-limit-distinct:{scope}" for scope, _, _, _ in normalized_identities}
        ):
            await self.tx.execute("SELECT pg_advisory_xact_lock(hashtextextended(?,0))", (key,))
        now = at_ms if at_ms is not None else await self._database_now_ms()
        for key, maximum, window in normalized_buckets:
            cutoff = now - window
            await self.tx.execute(
                "DELETE FROM quarantine_rate_limit_events WHERE bucket=? AND occurred_at_ms<=?",
                (key, cutoff),
            )
            row = (
                await self.tx.fetchone(
                    "SELECT COUNT(*) count FROM quarantine_rate_limit_events WHERE bucket=?", (key,)
                )
                or {}
            )
            if int(row.get("count") or 0) >= maximum:
                raise rate_limited()
        by_scope: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
        for scope, identity, maximum, window in normalized_identities:
            by_scope[scope].append((identity, maximum, window))
        for scope, values in by_scope.items():
            maximum, window = values[0][1], values[0][2]
            cutoff = now - window
            await self.tx.execute(
                "DELETE FROM quarantine_rate_limit_identities WHERE scope=? AND occurred_at_ms<=?",
                (scope, cutoff),
            )
            row = (
                await self.tx.fetchone(
                    "SELECT COUNT(*) count FROM quarantine_rate_limit_identities WHERE scope=?",
                    (scope,),
                )
                or {}
            )
            existing = 0
            for identity, _, _ in values:
                found = await self.tx.fetchone(
                    "SELECT 1 present FROM quarantine_rate_limit_identities WHERE scope=? AND identity=?",
                    (scope, identity),
                )
                existing += int(found is not None)
            additions = len({identity for identity, _, _ in values}) - existing
            if int(row.get("count") or 0) + additions > maximum:
                raise rate_limited()
        for key, _, _ in normalized_buckets:
            await self.tx.execute(
                "INSERT INTO quarantine_rate_limit_events(bucket,occurred_at_ms) VALUES(?,?)",
                (key, now),
            )
        for scope, identity, _, _ in normalized_identities:
            await self.tx.execute(
                "INSERT INTO quarantine_rate_limit_identities(scope,identity,occurred_at_ms) VALUES(?,?,?) "
                "ON CONFLICT(scope,identity) DO UPDATE SET occurred_at_ms=EXCLUDED.occurred_at_ms",
                (scope, identity, now),
            )

    async def _database_now_ms(self) -> int:
        row = (
            await self.tx.fetchone(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms"
            )
            or {}
        )
        return int(row["now_ms"])


class PostgresRateLimiter:
    def __init__(self, database: Any) -> None:
        self.database = database

    async def initialize(self) -> None:
        async with self.database.transaction() as tx:
            await tx.execute(
                "CREATE TABLE IF NOT EXISTS quarantine_rate_limit_events "
                "(bucket TEXT NOT NULL, occurred_at_ms BIGINT NOT NULL)"
            )
            await tx.execute(
                "CREATE INDEX IF NOT EXISTS idx_quarantine_rate_limit_events_bucket "
                "ON quarantine_rate_limit_events(bucket, occurred_at_ms)"
            )
            await tx.execute(
                "CREATE TABLE IF NOT EXISTS quarantine_rate_limit_identities "
                "(scope TEXT NOT NULL, identity TEXT NOT NULL, occurred_at_ms BIGINT NOT NULL, "
                "PRIMARY KEY(scope, identity))"
            )
            await tx.execute(
                "CREATE INDEX IF NOT EXISTS idx_quarantine_rate_limit_identities_scope "
                "ON quarantine_rate_limit_identities(scope, occurred_at_ms)"
            )

    async def consume_many(self, buckets: list[Bucket], at_ms: int | None = None) -> None:
        await self.consume_many_distinct(buckets, [], at_ms)

    async def consume_many_distinct(
        self, buckets: list[Bucket], identities: list[Distinct], at_ms: int | None = None
    ) -> None:
        async with self.database.transaction() as tx:
            await _PostgresSession(tx).consume_many_distinct(buckets, identities, at_ms)

    async def with_identity_lock(
        self, identity: str, operation: Callable[[Any], Awaitable[T]]
    ) -> T:
        async with self.database.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(?,0))",
                (f"quarantine-identity:{identity}",),
            )
            return await operation(_PostgresSession(tx))
