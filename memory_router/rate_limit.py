from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Awaitable, Callable, TypeVar
from .errors import HttpError

T = TypeVar("T")

def rate_limited() -> HttpError:
    return HttpError(429, "quarantine_rate_limited", "too many quarantine writes")

class InMemoryRateLimiter:
    def __init__(self) -> None:
        self.events: dict[str, deque[int]] = defaultdict(deque)
        self.distinct: dict[str, dict[str, int]] = defaultdict(dict)
        self.locks: dict[str, asyncio.Lock] = {}
        self.guard = asyncio.Lock()

    async def consume_many(self, buckets: list[tuple[str, int, int]], at_ms: int | None = None) -> None:
        await self.consume_many_distinct(buckets, [], at_ms)

    async def consume_many_distinct(self, buckets: list[tuple[str, int, int]], identities: list[tuple[str, str, int, int]], at_ms: int | None = None) -> None:
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
            for scope, identity, maximum, window in identities:
                del identity, window
                if maximum > 0 and len(self.distinct[scope]) + len(additions[scope]) > maximum:
                    raise rate_limited()
            for queue in live:
                queue.append(now)
            for scope, identity, maximum, window in identities:
                if maximum > 0 and window > 0:
                    self.distinct[scope][identity] = now

    async def with_identity_lock(self, identity: str, operation: Callable[["InMemoryRateLimiter"], Awaitable[T]]) -> T:
        async with self.guard:
            lock = self.locks.setdefault(identity, asyncio.Lock())
        async with lock:
            return await operation(self)

class PostgresRateLimiter:
    def __init__(self, database: Any) -> None:
        self.database = database

    async def initialize(self) -> None:
        async with self.database.transaction() as tx:
            await tx.execute("CREATE TABLE IF NOT EXISTS quarantine_rate_limit_events (bucket TEXT NOT NULL, occurred_at_ms BIGINT NOT NULL)")
            await tx.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_rate_limit_events_bucket ON quarantine_rate_limit_events(bucket, occurred_at_ms)")
            await tx.execute("CREATE TABLE IF NOT EXISTS quarantine_rate_limit_identities (scope TEXT NOT NULL, identity TEXT NOT NULL, occurred_at_ms BIGINT NOT NULL, PRIMARY KEY(scope, identity))")
            await tx.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_rate_limit_identities_scope ON quarantine_rate_limit_identities(scope, occurred_at_ms)")

    async def consume_many(self, buckets: list[tuple[str, int, int]], at_ms: int | None = None) -> None:
        await self.consume_many_distinct(buckets, [], at_ms)

    async def consume_many_distinct(self, buckets: list[tuple[str, int, int]], identities: list[tuple[str, str, int, int]], at_ms: int | None = None) -> None:
        buckets = sorted({key:(key,maximum,window) for key,maximum,window in buckets if maximum > 0 and window > 0}.values())
        identities = sorted({(scope,identity):(scope,identity,maximum,window) for scope,identity,maximum,window in identities if maximum > 0 and window > 0}.values())
        if not buckets and not identities:
            return
        async with self.database.transaction() as tx:
            for key in sorted({f"rate-limit:{key}" for key,_,_ in buckets} | {f"rate-limit-distinct:{scope}" for scope,_,_,_ in identities}):
                await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended(?,0))", (key,))
            now = at_ms if at_ms is not None else int(time.time() * 1000)
            for key, maximum, window in buckets:
                cutoff = now - window
                await tx.execute("DELETE FROM quarantine_rate_limit_events WHERE bucket=? AND occurred_at_ms<=?", (key, cutoff))
                row = await tx.fetchone("SELECT COUNT(*) count FROM quarantine_rate_limit_events WHERE bucket=?", (key,)) or {}
                if int(row.get("count") or 0) >= maximum:
                    raise rate_limited()
            by_scope: dict[str, list[tuple[str,int,int]]] = defaultdict(list)
            for scope, identity, maximum, window in identities:
                by_scope[scope].append((identity, maximum, window))
            for scope, values in by_scope.items():
                maximum, window = values[0][1], values[0][2]
                cutoff = now - window
                await tx.execute("DELETE FROM quarantine_rate_limit_identities WHERE scope=? AND occurred_at_ms<=?", (scope, cutoff))
                row = await tx.fetchone("SELECT COUNT(*) count FROM quarantine_rate_limit_identities WHERE scope=?", (scope,)) or {}
                existing = 0
                for identity, _, _ in values:
                    found = await tx.fetchone("SELECT 1 present FROM quarantine_rate_limit_identities WHERE scope=? AND identity=?", (scope, identity))
                    existing += 1 if found else 0
                additions = len({identity for identity,_,_ in values}) - existing
                if int(row.get("count") or 0) + additions > maximum:
                    raise rate_limited()
            for key, _, _ in buckets:
                await tx.execute("INSERT INTO quarantine_rate_limit_events(bucket,occurred_at_ms) VALUES(?,?)", (key, now))
            for scope, identity, _, _ in identities:
                if tx.dialect == "postgres":
                    await tx.execute("INSERT INTO quarantine_rate_limit_identities(scope,identity,occurred_at_ms) VALUES(?,?,?) ON CONFLICT(scope,identity) DO UPDATE SET occurred_at_ms=EXCLUDED.occurred_at_ms", (scope,identity,now))

    async def with_identity_lock(self, identity: str, operation: Callable[["PostgresRateLimiter"], Awaitable[T]]) -> T:
        async with self.database.transaction() as tx:
            await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended(?,0))", (f"quarantine-identity:{identity}",))
        return await operation(self)
