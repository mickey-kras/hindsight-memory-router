from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable, Sequence, TypeVar

from .config import HindsightLimitConfig
from .errors import HttpError
from .models import RecallBody, RetainBody
from .quarantine.db import PostgresDatabase, SqlSession

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Rule:
    max: int
    window_ms: int


@dataclass(frozen=True, slots=True)
class Bucket:
    key: str
    rule: Rule


@dataclass(frozen=True, slots=True)
class DistinctIdentity:
    scope: str
    identity: str
    rule: Rule


def quarantine_rate_limit_error() -> HttpError:
    return HttpError(429, "quarantine_rate_limited", "too many quarantine writes")


class InMemorySlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, list[int]] = {}
        self._distinct: dict[str, dict[str, int]] = {}
        self._identity_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def consume(self, key: str, rule: Rule, at_ms: int | None = None) -> None:
        await self.consume_many((Bucket(key, rule),), at_ms=at_ms)

    async def consume_many(self, buckets: Sequence[Bucket], at_ms: int | None = None) -> None:
        await self.consume_many_distinct(buckets, (), at_ms=at_ms)

    async def consume_many_distinct(
        self,
        buckets: Sequence[Bucket],
        identities: Sequence[DistinctIdentity],
        at_ms: int | None = None,
    ) -> None:
        enabled = _normalize_buckets(buckets)
        distinct = _normalize_distinct(identities)
        if not enabled and not distinct:
            return
        now = int(time.time() * 1000) if at_ms is None else at_ms
        async with self._lock:
            live_buckets: dict[str, list[int]] = {}
            for bucket in enabled:
                cutoff = now - bucket.rule.window_ms
                events = [event for event in self._buckets.get(bucket.key, []) if event > cutoff]
                if len(events) >= bucket.rule.max:
                    raise quarantine_rate_limit_error()
                live_buckets[bucket.key] = events
            live_distinct: dict[str, dict[str, int]] = {}
            additions: defaultdict[str, set[str]] = defaultdict(set)
            for identity in distinct:
                cutoff = now - identity.rule.window_ms
                values = {
                    key: value
                    for key, value in self._distinct.get(identity.scope, {}).items()
                    if value > cutoff
                }
                live_distinct[identity.scope] = values
                if identity.identity not in values:
                    additions[identity.scope].add(identity.identity)
            for identity in distinct:
                values = live_distinct[identity.scope]
                if len(values) + len(additions[identity.scope]) > identity.rule.max:
                    raise quarantine_rate_limit_error()
            for bucket in enabled:
                live_buckets[bucket.key].append(now)
                self._buckets[bucket.key] = live_buckets[bucket.key]
            for identity in distinct:
                values = live_distinct[identity.scope]
                values[identity.identity] = now
                self._distinct[identity.scope] = values

    async def with_identity_lock(
        self, identity_key: str, operation: Callable[["InMemorySlidingWindowRateLimiter"], Awaitable[T]]
    ) -> T:
        lock = self._identity_locks[identity_key]
        async with lock:
            return await operation(self)


class PostgresSlidingWindowRateLimiter:
    def __init__(self, url: str) -> None:
        self._db = PostgresDatabase(url)

    async def initialize(self) -> None:
        await self._db.initialize()
        async with self._db.transaction() as tx:
            await tx.execute_script(
                """
                CREATE TABLE IF NOT EXISTS quarantine_rate_limit_events (
                  bucket TEXT NOT NULL,
                  occurred_at_ms BIGINT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_quarantine_rate_limit_events_bucket
                  ON quarantine_rate_limit_events(bucket, occurred_at_ms);
                CREATE TABLE IF NOT EXISTS quarantine_rate_limit_identities (
                  scope TEXT NOT NULL,
                  identity TEXT NOT NULL,
                  occurred_at_ms BIGINT NOT NULL,
                  PRIMARY KEY(scope, identity)
                );
                CREATE INDEX IF NOT EXISTS idx_quarantine_rate_limit_identities_scope
                  ON quarantine_rate_limit_identities(scope, occurred_at_ms);
                """
            )

    async def close(self) -> None:
        await self._db.close()

    async def consume(self, key: str, rule: Rule, at_ms: int | None = None) -> None:
        await self.consume_many((Bucket(key, rule),), at_ms=at_ms)

    async def consume_many(self, buckets: Sequence[Bucket], at_ms: int | None = None) -> None:
        await self.consume_many_distinct(buckets, (), at_ms=at_ms)

    async def consume_many_distinct(
        self,
        buckets: Sequence[Bucket],
        identities: Sequence[DistinctIdentity],
        at_ms: int | None = None,
    ) -> None:
        enabled = _normalize_buckets(buckets)
        distinct = _normalize_distinct(identities)
        if not enabled and not distinct:
            return
        async with self._db.transaction() as tx:
            await self._consume_in_tx(tx, enabled, distinct, at_ms)

    async def with_identity_lock(
        self, identity_key: str, operation: Callable[["_PgSessionAdapter"], Awaitable[T]]
    ) -> T:
        async with self._db.transaction() as tx:
            await tx.run(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"quarantine-identity:{identity_key}",),
            )
            return await operation(_PgSessionAdapter(self, tx))

    async def _consume_in_tx(
        self,
        tx: SqlSession,
        buckets: Sequence[Bucket],
        identities: Sequence[DistinctIdentity],
        at_ms: int | None,
    ) -> None:
        lock_keys = sorted(
            {
                *(f"rate-limit:{bucket.key}" for bucket in buckets),
                *(f"rate-limit-distinct:{identity.scope}" for identity in identities),
            }
        )
        for key in lock_keys:
            await tx.run(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (key,)
            )
        if at_ms is None:
            row = await tx.get(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms"
            )
            now = int((row or {})["now_ms"])
        else:
            now = at_ms
        for bucket in buckets:
            cutoff = now - bucket.rule.window_ms
            await tx.run(
                "DELETE FROM quarantine_rate_limit_events WHERE bucket=%s AND occurred_at_ms <= %s",
                (bucket.key, cutoff),
            )
            row = await tx.get(
                "SELECT COUNT(*) AS count FROM quarantine_rate_limit_events WHERE bucket=%s",
                (bucket.key,),
            )
            if int((row or {}).get("count") or 0) >= bucket.rule.max:
                raise quarantine_rate_limit_error()
        grouped: defaultdict[str, list[DistinctIdentity]] = defaultdict(list)
        for identity in identities:
            grouped[identity.scope].append(identity)
        for scope, values in grouped.items():
            rule = values[0].rule
            cutoff = now - rule.window_ms
            await tx.run(
                "DELETE FROM quarantine_rate_limit_identities WHERE scope=%s AND occurred_at_ms <= %s",
                (scope, cutoff),
            )
            row = await tx.get(
                "SELECT COUNT(*) AS count FROM quarantine_rate_limit_identities WHERE scope=%s",
                (scope,),
            )
            existing_rows = await tx.all(
                "SELECT identity FROM quarantine_rate_limit_identities WHERE scope=%s",
                (scope,),
            )
            existing = {str(entry["identity"]) for entry in existing_rows}
            additions = {entry.identity for entry in values if entry.identity not in existing}
            if int((row or {}).get("count") or 0) + len(additions) > rule.max:
                raise quarantine_rate_limit_error()
        for bucket in buckets:
            await tx.run(
                "INSERT INTO quarantine_rate_limit_events(bucket,occurred_at_ms) VALUES(%s,%s)",
                (bucket.key, now),
            )
        for identity in identities:
            await tx.run(
                """INSERT INTO quarantine_rate_limit_identities(scope,identity,occurred_at_ms)
                   VALUES(%s,%s,%s)
                   ON CONFLICT(scope,identity) DO UPDATE
                   SET occurred_at_ms=EXCLUDED.occurred_at_ms""",
                (identity.scope, identity.identity, now),
            )


class _PgSessionAdapter:
    def __init__(self, owner: PostgresSlidingWindowRateLimiter, tx: SqlSession) -> None:
        self._owner, self._tx = owner, tx

    async def consume(self, key: str, rule: Rule, at_ms: int | None = None) -> None:
        await self._owner._consume_in_tx(self._tx, _normalize_buckets((Bucket(key, rule),)), (), at_ms)

    async def consume_many(self, buckets: Sequence[Bucket], at_ms: int | None = None) -> None:
        await self._owner._consume_in_tx(self._tx, _normalize_buckets(buckets), (), at_ms)

    async def consume_many_distinct(
        self, buckets: Sequence[Bucket], identities: Sequence[DistinctIdentity], at_ms: int | None = None
    ) -> None:
        await self._owner._consume_in_tx(
            self._tx, _normalize_buckets(buckets), _normalize_distinct(identities), at_ms
        )


class HindsightLimits:
    def __init__(self, config: HindsightLimitConfig, limiter: Any) -> None:
        self.config = config
        self.limiter = limiter

    def assert_retain_bounds(self, body: RetainBody) -> None:
        if len(body.items) > self.config.max_retain_items:
            raise HttpError(
                413,
                "retain_item_limit_exceeded",
                "retain request contains too many memory items",
            )
        if _string_value_bytes(body.model_dump_wire()) > self.config.max_retain_content_bytes:
            raise HttpError(
                413,
                "retain_content_too_large",
                "retain content exceeds the configured byte limit",
            )

    def assert_recall_bounds(self, body: RecallBody) -> None:
        if len(body.query.encode("utf-8")) > self.config.max_recall_query_bytes:
            raise HttpError(
                413, "recall_query_too_large", "recall query exceeds the configured byte limit"
            )
        if body.max_tokens is not None and body.max_tokens > self.config.max_recall_max_tokens:
            raise HttpError(
                413,
                "recall_max_tokens_exceeded",
                "recall max_tokens exceeds the configured limit",
            )

    async def consume_retain(self, writer_id: str) -> None:
        await self._consume("retain", writer_id, self.config.retain_writer_max, self.config.retain_global_max)

    async def consume_recall(self, writer_id: str) -> None:
        await self._consume("recall", writer_id, self.config.recall_writer_max, self.config.recall_global_max)

    async def _consume(self, kind: str, writer_id: str, writer_max: int, global_max: int) -> None:
        try:
            await self.limiter.consume_many(
                (
                    Bucket(f"hindsight:{kind}:writer:{writer_id}", Rule(writer_max, self.config.rate_limit_window_ms)),
                    Bucket(f"hindsight:{kind}:global", Rule(global_max, self.config.rate_limit_window_ms)),
                )
            )
        except HttpError as exc:
            if exc.status == 429:
                raise HttpError(
                    429,
                    "hindsight_rate_limited",
                    f"too many Hindsight {kind} requests",
                    {"retry-after": str(max(1, (self.config.rate_limit_window_ms + 999) // 1000))},
                ) from exc
            raise


def _normalize_buckets(buckets: Iterable[Bucket]) -> list[Bucket]:
    result: dict[str, Bucket] = {}
    for bucket in buckets:
        if bucket.rule.max > 0 and bucket.rule.window_ms > 0:
            result[bucket.key] = bucket
    return sorted(result.values(), key=lambda item: item.key)


def _normalize_distinct(values: Iterable[DistinctIdentity]) -> list[DistinctIdentity]:
    result: dict[tuple[str, str], DistinctIdentity] = {}
    for value in values:
        if value.rule.max > 0 and value.rule.window_ms > 0:
            result[(value.scope, value.identity)] = value
    return sorted(result.values(), key=lambda item: (item.scope, item.identity))


def _string_value_bytes(value: Any) -> int:
    pending = [value]
    total = 0
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            total += len(current.encode("utf-8"))
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, dict):
            pending.extend(current.values())
    return total
