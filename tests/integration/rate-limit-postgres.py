from __future__ import annotations

import asyncio
import json
import os
import statistics
import time
import uuid

from psycopg import sql
from psycopg.conninfo import make_conninfo

from memory_router.db import PostgresDatabase, PostgresTx, create_backend
from memory_router.errors import HttpError
from memory_router.rate_limit import (
    ADVISORY_LOCK_SQL,
    Bucket,
    Distinct,
    PostgresRateLimiter,
    RateLimitConsumer,
    _database_now_ms,
    _PostgresSession,
    rate_limited,
)


async def admitted(
    limiter: RateLimitConsumer, buckets: list[Bucket], identities: list[Distinct], now: int
) -> bool:
    try:
        await limiter.consume_many_distinct(buckets, identities, at_ms=now)
    except HttpError as error:
        assert error.status == 429 and error.code == "quarantine_rate_limited"
        return False
    return True


async def parity_trace(limiter: RateLimitConsumer) -> list[bool]:
    short, long = Bucket("boundary-short-'雪,{}", 1, 10), Bucket("boundary-long", 1, 20)
    spare = Bucket("distinct-spare", 1, 100)
    old, new = Distinct("boundary-scope", "old", 1, 10), Distinct("boundary-scope", "new", 1, 10)
    operations = [
        ([short, long], [], 0),
        ([long, short], [], 9),
        ([short, long], [], 10),
        ([short], [], 10),
        ([long], [], 19),
        ([short, long], [], 20),
        ([], [old], 0),
        ([spare], [new], 1),
        ([spare], [], 1),
        ([], [old], 9),
        ([], [new], 18),
        ([], [new], 19),
        ([short], [Distinct("bucket-rejected-scope", "blocked", 1, 100)], 21),
        ([], [Distinct("bucket-rejected-scope", "accepted", 1, 100)], 21),
    ]
    results = [
        await admitted(limiter, buckets, identities, now) for buckets, identities, now in operations
    ]
    assert results == [
        True,
        False,
        False,
        True,
        False,
        True,
        True,
        False,
        True,
        True,
        False,
        True,
        False,
        True,
    ], results
    return results


async def verify_concurrent(
    first: PostgresRateLimiter, second: PostgresRateLimiter, *, distinct: bool
) -> None:
    prefix = "concurrent-distinct" if distinct else "concurrent-events"
    expected = 5 if distinct else 7

    async def consume(index: int) -> bool:
        buckets = [Bucket(f"{prefix}-shared", 7, 100), Bucket(f"{prefix}-{index}", 1, 100)]
        if index % 2:
            buckets.reverse()
        return await admitted(
            first if index % 2 else second,
            buckets,
            [Distinct(prefix, str(index), 5, 100)] if distinct else [],
            1000,
        )

    async with asyncio.timeout(10):
        results = await asyncio.gather(*(consume(index) for index in range(20)))
    assert sum(results) == expected, results
    async with first.database.transaction() as tx:
        events = await tx.fetchall(
            "SELECT bucket,COUNT(*) count FROM quarantine_rate_limit_events "
            "WHERE bucket LIKE ? GROUP BY bucket",
            (prefix + "-%",),
        )
        counts = {row["bucket"]: row["count"] for row in events}
        assert counts.pop(f"{prefix}-shared") == expected, counts
        assert counts == {
            f"{prefix}-{index}": 1 for index, result in enumerate(results) if result
        }, counts
        identities = await tx.fetchall(
            "SELECT identity FROM quarantine_rate_limit_identities WHERE scope=?", (prefix,)
        )
        assert {row["identity"] for row in identities} == {
            str(index) for index, result in enumerate(results) if distinct and result
        }


async def verify_rollback(limiter: PostgresRateLimiter) -> None:
    cache_before = limiter.max_window_cache[0]
    async with limiter.database.transaction() as tx:
        state_before = await tx.fetchone(
            "SELECT max_window_ms FROM quarantine_rate_limit_state WHERE id=1"
        )

    async def fail_after_admission(session: RateLimitConsumer) -> None:
        await session.consume_many_distinct(
            [Bucket("rollback-a", 1, 120_000), Bucket("rollback-z", 1, 120_000)],
            [Distinct("rollback-scope", "one", 1, 120_000)],
            at_ms=1000,
        )
        raise ValueError("rollback probe")

    try:
        await limiter.with_identity_lock("rollback", fail_after_admission)
    except ValueError as error:
        assert str(error) == "rollback probe"
    else:
        raise AssertionError("rollback probe unexpectedly committed")
    assert limiter.max_window_cache[0] == cache_before
    async with limiter.database.transaction() as tx:
        assert not await tx.fetchall(
            "SELECT bucket FROM quarantine_rate_limit_events WHERE bucket LIKE 'rollback-%'"
        )
        assert not await tx.fetchall(
            "SELECT identity FROM quarantine_rate_limit_identities WHERE scope='rollback-scope'"
        )
        assert (
            await tx.fetchone("SELECT max_window_ms FROM quarantine_rate_limit_state WHERE id=1")
            == state_before
        )


async def verify_rejection_rollback(limiter: PostgresRateLimiter) -> None:
    expired, full = Bucket("rejection-expired", 1, 10), Bucket("rejection-full", 1, 100)
    identity = Distinct("rejection-scope", "old", 1, 100)
    assert await admitted(limiter, [expired, full], [identity], 0)
    for buckets, identities in (
        ([expired, full], []),
        ([expired], [Distinct(identity.scope, "new", 1, 100)]),
    ):
        assert not await admitted(limiter, buckets, identities, 10)
        async with limiter.database.transaction() as tx:
            events = await tx.fetchall(
                "SELECT bucket,occurred_at_ms FROM quarantine_rate_limit_events "
                "WHERE bucket=ANY(?::text[]) ORDER BY bucket",
                ([expired.key, full.key],),
            )
            assert events == [
                {"bucket": expired.key, "occurred_at_ms": 0},
                {"bucket": full.key, "occurred_at_ms": 0},
            ], events
            assert await tx.fetchall(
                "SELECT identity,occurred_at_ms FROM quarantine_rate_limit_identities WHERE scope=?",
                (identity.scope,),
            ) == [{"identity": "old", "occurred_at_ms": 0}]


async def verify_clock_after_lock(database: PostgresDatabase, peer: PostgresDatabase) -> None:
    bucket = Bucket("clock-after-lock", 1, 100)
    async with peer.pool.connection() as waiter_connection:
        waiter_tx = PostgresTx(waiter_connection)
        async with database.transaction() as holder:
            await holder.execute(ADVISORY_LOCK_SQL, (f"rate-limit:{bucket.key}",))

            async def wait_and_consume() -> None:
                async with waiter_connection.transaction():
                    await _PostgresSession(waiter_tx).consume_many([bucket])

            task = asyncio.create_task(wait_and_consume())
            try:
                async with asyncio.timeout(5):
                    while True:
                        row = await holder.fetchone(
                            "SELECT cardinality(pg_blocking_pids(?)) count",
                            (waiter_connection.info.backend_pid,),
                        )
                        if row and row["count"] > 0:
                            break
                        await asyncio.sleep(0.01)
                    recorded = await _database_now_ms(holder)
                    await holder.execute(
                        "INSERT INTO quarantine_rate_limit_events(bucket,occurred_at_ms) VALUES(?,?)",
                        (bucket.key, recorded),
                    )
                    while await _database_now_ms(holder) < recorded + bucket.window_ms:
                        await asyncio.sleep(0.01)
            except BaseException:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                raise
        async with asyncio.timeout(5):
            await task
    async with database.transaction() as tx:
        events = await tx.fetchall(
            "SELECT occurred_at_ms FROM quarantine_rate_limit_events WHERE bucket=?", (bucket.key,)
        )
        assert len(events) == 1 and events[0]["occurred_at_ms"] >= recorded + bucket.window_ms, (
            events
        )


class BaselineSession(_PostgresSession):
    async def _check_buckets(self, buckets: list[Bucket], now: int) -> None:
        for key, maximum, window in buckets:
            await self.tx.execute(
                "DELETE FROM quarantine_rate_limit_events WHERE bucket=? AND occurred_at_ms<=?",
                (key, now - window),
            )
            row = await self.tx.fetchone(
                "SELECT COUNT(*) count FROM quarantine_rate_limit_events WHERE bucket=?", (key,)
            )
            if row and int(row["count"]) >= maximum:
                raise rate_limited()

    async def _insert_buckets(self, buckets: list[Bucket], now: int) -> None:
        for key, _, _ in buckets:
            await self.tx.execute(
                "INSERT INTO quarantine_rate_limit_events(bucket,occurred_at_ms) VALUES(?,?)",
                (key, now),
            )


async def benchmark(database: PostgresDatabase) -> None:
    rtts = []
    async with database.transaction() as tx:
        for _ in range(30):
            started = time.perf_counter()
            await tx.fetchone("SELECT 1")
            rtts.append(time.perf_counter() - started)
        version = await tx.fetchone("SHOW server_version")
    print(
        json.dumps(
            {
                "probe": "postgres_select_1_rtt",
                "version": version,
                "samples_seconds": rtts,
                "p50_ms": statistics.median(rtts) * 1000,
            }
        )
    )
    for concurrency in (1, 5):
        for repeat in range(3):
            variants = [("baseline", BaselineSession), ("batched", _PostgresSession)]
            if repeat % 2:
                variants.reverse()
            for name, session_type in variants:
                prefix = f"benchmark-{name}-{concurrency}-{repeat}"
                keys = [
                    f"{prefix}-{worker}-{index}"
                    for worker in range(concurrency)
                    for index in range(2)
                ]
                async with database.transaction() as tx:
                    await tx.execute(
                        "INSERT INTO quarantine_rate_limit_events(bucket,occurred_at_ms) "
                        "SELECT bucket,floor(extract(epoch FROM clock_timestamp())*1000)::bigint "
                        "FROM unnest(?::text[]) AS seed(bucket) CROSS JOIN generate_series(1,16)",
                        (keys,),
                    )
                durations = []

                async def worker(
                    index: int,
                    prefix: str = prefix,
                    session_type: type[_PostgresSession] = session_type,
                    durations: list[float] = durations,
                ) -> None:
                    buckets = [
                        Bucket(f"{prefix}-{index}-{suffix}", 100_000, 60_000) for suffix in range(2)
                    ]
                    for _ in range(20):
                        started = time.perf_counter()
                        async with database.transaction() as tx:
                            await session_type(tx, max_window_cache=[60_000]).consume_many(buckets)
                        durations.append(time.perf_counter() - started)

                started = time.perf_counter()
                await asyncio.gather(*(worker(index) for index in range(concurrency)))
                elapsed = time.perf_counter() - started
                print(
                    json.dumps(
                        {
                            "probe": "postgres_warm_two_bucket_admission",
                            "variant": name,
                            "concurrency": concurrency,
                            "repeat": repeat,
                            "sql_calls_excluding_transaction_control": 9
                            if name == "baseline"
                            else 6,
                            "samples_seconds": durations,
                            "p50_ms": statistics.median(durations) * 1000,
                            "admissions_per_second": len(durations) / elapsed,
                        }
                    )
                )
                async with database.transaction() as tx:
                    await tx.execute(
                        "DELETE FROM quarantine_rate_limit_events WHERE bucket=ANY(?::text[])",
                        (keys,),
                    )


async def verify() -> None:
    url = os.environ["QUARANTINE_DATABASE_URL"]
    schema = "quota_probe_" + uuid.uuid4().hex
    control = PostgresDatabase(url)
    await control.initialize()
    first_db = second_db = sqlite = None
    try:
        async with control.pool.connection() as connection:
            await connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        scoped_url = make_conninfo(url, options=f"-csearch_path={schema}")
        first_db, second_db = PostgresDatabase(scoped_url), PostgresDatabase(scoped_url)
        await first_db.initialize()
        await second_db.initialize()
        first, second = PostgresRateLimiter(first_db), PostgresRateLimiter(second_db)
        await first.initialize()
        await second.initialize()
        sqlite = await create_backend("sqlite::memory:")
        assert await parity_trace(first) == await parity_trace(sqlite.rate_limiter)
        await verify_concurrent(first, second, distinct=False)
        await verify_concurrent(first, second, distinct=True)
        await verify_rollback(first)
        await verify_rejection_rollback(first)
        await verify_clock_after_lock(first_db, second_db)
        print(
            "PostgreSQL quota boundaries, SQLite parity, concurrent consumers, rollback and post-lock database clock passed"
        )
        await benchmark(first_db)
    finally:
        if sqlite is not None:
            await sqlite.database.close()
        if second_db is not None:
            await second_db.close()
        if first_db is not None:
            await first_db.close()
        async with control.pool.connection() as connection:
            await connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
        await control.close()


if __name__ == "__main__":
    asyncio.run(verify())
