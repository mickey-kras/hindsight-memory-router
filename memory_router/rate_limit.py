from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from typing import Any, NoReturn, TypeVar

from .errors import HttpError
from .logging import log_event

T = TypeVar("T")
Bucket = tuple[str, int, int]
Distinct = tuple[str, str, int, int]
_SWEEP_EVERY = 128
logger = logging.getLogger(__name__)


class ConcurrencyLeaseUnavailable(RuntimeError):
    pass


class ConcurrencyLeaseLost(ConcurrencyLeaseUnavailable):
    pass


class ConcurrencyLeaseRefreshFailed(ConcurrencyLeaseUnavailable):
    pass


def rate_limited() -> HttpError:
    return HttpError(429, "quarantine_rate_limited", "too many quarantine writes")


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self.events: dict[str, deque[int]] = defaultdict(deque)
        self.event_windows: dict[str, int] = {}
        self.distinct: dict[str, dict[str, int]] = defaultdict(dict)
        self.distinct_windows: dict[str, int] = {}
        self.locks: dict[str, tuple[asyncio.Lock, int]] = {}
        self.guard = asyncio.Lock()
        self.consume_count = 0

    async def consume_many(self, buckets: list[Bucket], at_ms: int | None = None) -> None:
        await self.consume_many_distinct(buckets, [], at_ms)

    async def consume_many_distinct(
        self, buckets: list[Bucket], identities: list[Distinct], at_ms: int | None = None
    ) -> None:
        now = at_ms if at_ms is not None else int(time.time() * 1000)
        async with self.guard:
            self.consume_count += 1
            if self.consume_count % _SWEEP_EVERY == 0:
                self._sweep_stale(now)
            live: list[tuple[str, deque[int]]] = []
            for key, maximum, window in buckets:
                if maximum <= 0 or window <= 0:
                    continue
                self.event_windows[key] = window
                queue = self.events[key]
                cutoff = now - window
                while queue and queue[0] <= cutoff:
                    queue.popleft()
                if len(queue) >= maximum:
                    raise rate_limited()
                live.append((key, queue))
            additions: dict[str, set[str]] = defaultdict(set)
            for scope, identity, maximum, window in identities:
                if maximum <= 0 or window <= 0:
                    continue
                self.distinct_windows[scope] = window
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
            for _, queue in live:
                queue.append(now)
            for scope, identity, maximum, window in identities:
                if maximum > 0 and window > 0:
                    self.distinct[scope][identity] = now
            self._drop_empty()

    def _sweep_stale(self, now: int) -> None:
        for key, queue in list(self.events.items()):
            window = self.event_windows.get(key)
            if window is None:
                continue
            cutoff = now - window
            while queue and queue[0] <= cutoff:
                queue.popleft()
        for scope, values in list(self.distinct.items()):
            window = self.distinct_windows.get(scope)
            if window is None:
                continue
            cutoff = now - window
            for identity, timestamp in list(values.items()):
                if timestamp <= cutoff:
                    del values[identity]
        self._drop_empty()

    def _drop_empty(self) -> None:
        for key, queue in list(self.events.items()):
            if not queue:
                self.events.pop(key, None)
                self.event_windows.pop(key, None)
        for scope, values in list(self.distinct.items()):
            if not values:
                self.distinct.pop(scope, None)
                self.distinct_windows.pop(scope, None)

    async def with_identity_lock(
        self, identity: str, operation: Callable[[InMemoryRateLimiter], Awaitable[T]]
    ) -> T:
        async with self.guard:
            lock, users = self.locks.get(identity, (asyncio.Lock(), 0))
            self.locks[identity] = (lock, users + 1)
        try:
            async with lock:
                return await operation(self)
        finally:
            async with self.guard:
                current = self.locks.get(identity)
                if current is not None and current[0] is lock:
                    remaining = current[1] - 1
                    if remaining == 0:
                        self.locks.pop(identity, None)
                    else:
                        self.locks[identity] = (lock, remaining)


class _PostgresSession:
    def __init__(
        self,
        tx: Any,
        *,
        global_sweep: bool = False,
        max_window_cache: list[int] | None = None,
    ) -> None:
        self.tx = tx
        self.global_sweep = global_sweep
        self.max_window_cache = max_window_cache
        self.observed_max_window: int | None = None

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
        windows = [window for _, _, window in normalized_buckets] + [
            window for _, _, _, window in normalized_identities
        ]
        await self._record_max_window(max(windows))
        if self.global_sweep:
            await self._global_sweep(now)
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

    async def _record_max_window(self, window: int) -> None:
        if self.max_window_cache is None and not self.global_sweep:
            return
        if self.max_window_cache is not None and window <= self.max_window_cache[0]:
            self.observed_max_window = self.max_window_cache[0]
            return
        row = (
            await self.tx.fetchone(
                "SELECT max_window_ms FROM quarantine_rate_limit_state WHERE id=1"
            )
            or {}
        )
        current = int(row.get("max_window_ms") or 0)
        if window > current:
            await self.tx.execute(
                "INSERT INTO quarantine_rate_limit_state(id,max_window_ms) VALUES(1,?) "
                "ON CONFLICT(id) DO UPDATE SET max_window_ms=GREATEST(quarantine_rate_limit_state.max_window_ms,EXCLUDED.max_window_ms)",
                (window,),
            )
        self.observed_max_window = max(current, window)

    async def _global_sweep(self, now: int) -> None:
        row = (
            await self.tx.fetchone(
                "SELECT max_window_ms FROM quarantine_rate_limit_state WHERE id=1"
            )
            or {}
        )
        max_window = int(row.get("max_window_ms") or 0)
        self.observed_max_window = max(self.observed_max_window or 0, max_window)
        if max_window <= 0:
            return
        cutoff = now - max_window
        await self.tx.execute(
            "DELETE FROM quarantine_rate_limit_events WHERE occurred_at_ms<=?", (cutoff,)
        )
        await self.tx.execute(
            "DELETE FROM quarantine_rate_limit_identities WHERE occurred_at_ms<=?", (cutoff,)
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
        self.consume_count = 0
        self.max_window_cache = [0]

    async def initialize(self) -> None:
        async with self.database.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(?,0))",
                ("rate-limit-schema",),
            )
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
            await tx.execute(
                "CREATE TABLE IF NOT EXISTS quarantine_rate_limit_state "
                "(id SMALLINT PRIMARY KEY, max_window_ms BIGINT NOT NULL)"
            )

    def _next_session(self, tx: Any) -> _PostgresSession:
        self.consume_count += 1
        return _PostgresSession(
            tx,
            global_sweep=self.consume_count % _SWEEP_EVERY == 0,
            max_window_cache=self.max_window_cache,
        )

    def _commit_session(self, session: _PostgresSession) -> None:
        if session.observed_max_window is not None:
            self.max_window_cache[0] = max(self.max_window_cache[0], session.observed_max_window)

    async def consume_many(self, buckets: list[Bucket], at_ms: int | None = None) -> None:
        await self.consume_many_distinct(buckets, [], at_ms)

    async def consume_many_distinct(
        self, buckets: list[Bucket], identities: list[Distinct], at_ms: int | None = None
    ) -> None:
        async with self.database.transaction() as tx:
            session = self._next_session(tx)
            await session.consume_many_distinct(buckets, identities, at_ms)
        self._commit_session(session)

    async def with_identity_lock(
        self, identity: str, operation: Callable[[Any], Awaitable[T]]
    ) -> T:
        async with self.database.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(?,0))",
                (f"quarantine-identity:{identity}",),
            )
            session = self._next_session(tx)
            result = await operation(session)
        self._commit_session(session)
        return result


class PostgresConcurrencyLimiter:
    def __init__(
        self,
        database: Any,
        *,
        lease_ms: int = 30_000,
        cleanup_timeout_seconds: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if lease_ms < 3_000:
            raise ValueError("lease_ms must be at least 3000")
        self.database = database
        self.lease_ms = lease_ms
        self.cleanup_timeout_seconds = cleanup_timeout_seconds
        self.clock = clock
        self.sleep = sleep

    async def initialize(self) -> None:
        async with self.database.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(?,0))",
                ("rate-limit-schema",),
            )
            await tx.execute(
                "CREATE TABLE IF NOT EXISTS principal_concurrency_leases "
                "(bucket TEXT NOT NULL, lease_id TEXT NOT NULL, expires_at_ms BIGINT NOT NULL, "
                "PRIMARY KEY(bucket, lease_id))"
            )
            await tx.execute(
                "CREATE INDEX IF NOT EXISTS idx_principal_concurrency_leases_bucket_expiry "
                "ON principal_concurrency_leases(bucket, expires_at_ms)"
            )

    async def run(self, bucket: str, maximum: int, operation: Callable[[], Awaitable[T]]) -> T:
        lease_id = str(uuid.uuid4())
        try:
            await self._acquire(bucket, lease_id, maximum)
        except HttpError:
            raise
        except Exception as exc:
            raise ConcurrencyLeaseUnavailable(
                "principal concurrency lease acquisition failed"
            ) from exc
        operation_task: asyncio.Future[T] | None = None
        heartbeat: asyncio.Task[None] | None = None
        try:
            operation_task = asyncio.ensure_future(operation())
            heartbeat = asyncio.create_task(self._heartbeat(bucket, lease_id))
            tasks: set[asyncio.Future[Any]] = {operation_task, heartbeat}
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if operation_task in done:
                return await operation_task
            await heartbeat
        finally:
            tasks_to_stop = [task for task in (operation_task, heartbeat) if task is not None]
            for task in tasks_to_stop:
                task.cancel()
            await asyncio.gather(*tasks_to_stop, return_exceptions=True)
            try:
                await asyncio.wait_for(
                    self._release(bucket, lease_id), timeout=self.cleanup_timeout_seconds
                )
            except Exception as exc:
                log_event(
                    logger,
                    "error",
                    "principal_concurrency_release_failed",
                    operation="release-concurrency-lease",
                    error_kind="storage",
                    error=exc,
                    outcome="degraded",
                )

    async def _acquire(self, bucket: str, lease_id: str, maximum: int) -> None:
        async with self.database.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(?,0))",
                (f"principal-concurrency:{bucket}",),
            )
            now = await self._database_now_ms(tx)
            await tx.execute(
                "DELETE FROM principal_concurrency_leases WHERE bucket=? AND expires_at_ms<=?",
                (bucket, now),
            )
            row = (
                await tx.fetchone(
                    "SELECT COUNT(*) count FROM principal_concurrency_leases WHERE bucket=?",
                    (bucket,),
                )
                or {}
            )
            if int(row.get("count") or 0) >= maximum:
                raise HttpError(
                    429,
                    "principal_concurrency_limited",
                    "too many concurrent requests for principal",
                    headers={"retry-after": "1"},
                )
            await tx.execute(
                "INSERT INTO principal_concurrency_leases(bucket,lease_id,expires_at_ms) "
                "VALUES(?,?,?)",
                (bucket, lease_id, now + self.lease_ms),
            )

    async def _heartbeat(self, bucket: str, lease_id: str) -> NoReturn:
        interval = self.lease_ms / 3000
        deadline = self.clock() + self.lease_ms / 1000
        next_delay = interval
        while True:
            await self.sleep(next_delay)
            try:
                await asyncio.wait_for(self._refresh(bucket, lease_id), timeout=interval / 2)
            except ConcurrencyLeaseLost:
                raise
            except Exception as exc:
                remaining = deadline - self.clock()
                if remaining <= interval:
                    raise ConcurrencyLeaseRefreshFailed(
                        "principal concurrency lease refresh failed"
                    ) from exc
                next_delay = min(1.0, remaining - interval)
                continue
            # PostgreSQL expiry is authoritative; monotonic time only bounds local retries.
            deadline = self.clock() + self.lease_ms / 1000
            next_delay = interval

    async def _refresh(self, bucket: str, lease_id: str) -> None:
        async with self.database.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(?,0))",
                (f"principal-concurrency:{bucket}",),
            )
            now = await self._database_now_ms(tx)
            row = await tx.fetchone(
                "UPDATE principal_concurrency_leases SET expires_at_ms=? "
                "WHERE bucket=? AND lease_id=? AND expires_at_ms>? RETURNING lease_id",
                (now + self.lease_ms, bucket, lease_id, now),
            )
            if row is None:
                raise ConcurrencyLeaseLost("principal concurrency lease was lost")

    async def _release(self, bucket: str, lease_id: str) -> None:
        async with self.database.transaction() as tx:
            await tx.execute(
                "DELETE FROM principal_concurrency_leases WHERE bucket=? AND lease_id=?",
                (bucket, lease_id),
            )

    @staticmethod
    async def _database_now_ms(tx: Any) -> int:
        row = (
            await tx.fetchone(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms"
            )
            or {}
        )
        return int(row["now_ms"])
