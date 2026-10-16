from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import AsyncExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.db import PostgresDatabase, create_backend, is_postgres
from memory_router.envelope import _PreparedDecrypted, decrypt_envelope
from memory_router.errors import HttpError
from memory_router.maintenance import cleanup, sweep_expired
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore, _deduped_id
from memory_router.rate_limit import InMemoryRateLimiter, PostgresRateLimiter, RateLimiter
from memory_router.repository import QuarantineRepository
from memory_router.review_repository import claim_review

AT = "2026-08-08T00:00:00.000Z"
LATER = "2026-08-10T00:00:00.000Z"


def admission(kind: str = "retain_request") -> dict[str, Any]:
    return {
        "timestamp": AT,
        "kind": kind,
        "reason": "suspicious_content",
        "writerId": "main",
        "sourceBank": "main" if kind == "recalled_memory" else None,
        "sourceMemoryId": "m" if kind == "recalled_memory" else None,
        "dedupeKey": "d" if kind != "recalled_memory" else None,
        "payload": {"items": [{"content": "x"}]},
    }


class PausedStore(QuarantineStore):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.wrapping = asyncio.Event()
        self.resume = asyncio.Event()

    async def _encrypt(
        self,
        input_: dict[str, Any],
        quarantine_id: str,
        *,
        prepared: _PreparedDecrypted | None = None,
    ) -> dict[str, Any]:
        self.wrapping.set()
        await self.resume.wait()
        return await super()._encrypt(input_, quarantine_id, prepared=prepared)


class LegacyMemoryStore(PausedStore):
    def _resolve_id(self, input_: dict[str, Any]) -> str:
        # Before memoryv2, put/store used the same snapshot guard with this ID.
        assert input_["kind"] == "recalled_memory"
        return _deduped_id("memory", f"{input_['sourceBank']}:{input_['sourceMemoryId']}")


async def verify_memory_generation_race(
    repository: QuarantineRepository,
    other: QuarantineRepository,
    limiter: RateLimiter,
    peer_limiter: RateLimiter,
    public_pem: str,
    private_pem: str,
    *,
    legacy_first: bool,
) -> None:
    stores = [
        LegacyMemoryStore(public_pem, repository, QuarantineLimits(), limiter),
        PausedStore(public_pem, other, QuarantineLimits(), peer_limiter),
    ]
    value = {**admission("recalled_memory"), "sourceMemoryId": f"generation-{legacy_first}"}
    assert stores[0]._resolve_id(value) != stores[1]._resolve_id(value)
    writes = [asyncio.create_task(store.put(value)) for store in stores]
    try:
        # Both replicas prepare envelopes from the same absent-row snapshot.
        await asyncio.wait_for(asyncio.gather(*(store.wrapping.wait() for store in stores)), 5)
        first = 0 if legacy_first else 1
        stores[first].resume.set()
        winner = await asyncio.wait_for(writes[first], 5)
        before = await repository.find_memory_state("main", value["sourceMemoryId"])
        assert before and before["quarantine_id"] == winner["quarantine_id"]
        assert (
            decrypt_envelope(before["encrypted"], private_pem)["quarantine_id"]
            == before["quarantine_id"]
        )
        stores[1 - first].resume.set()
        try:
            await asyncio.wait_for(writes[1 - first], 5)
        except HttpError as error:
            assert error.status == 409 and error.code == "quarantine_write_stale"
        else:
            raise AssertionError("mixed-generation stale envelope was admitted")
        assert await repository.get(winner["quarantine_id"]) == before
        assert before["requarantine_count"] == 0
        assert await repository.get(stores[1 - first]._resolve_id(value)) is None

        # A fresh preflight reuses the persisted ID before preparing its envelope.
        retry = await asyncio.wait_for(stores[1 - first].put(value), 5)
        assert retry == winner
        saved = await repository.get(winner["quarantine_id"])
        assert saved and saved["requarantine_count"] == 1
        assert (
            decrypt_envelope(saved["encrypted"], private_pem)["quarantine_id"]
            == saved["quarantine_id"]
        )
    finally:
        for store in stores:
            store.resume.set()
        for write in writes:
            write.cancel()
        await asyncio.gather(*writes, return_exceptions=True)


async def budget(limiter: RateLimiter) -> tuple[dict[str, int], dict[str, int]]:
    if isinstance(limiter, InMemoryRateLimiter):
        return (
            {key: len(values) for key, values in limiter.events.items()},
            {key: len(values) for key, values in limiter.distinct.items()},
        )
    assert isinstance(limiter, PostgresRateLimiter)
    async with limiter.database.transaction() as tx:
        events = await tx.fetchall(
            "SELECT bucket, COUNT(*) count FROM quarantine_rate_limit_events GROUP BY bucket"
        )
        identities = await tx.fetchall(
            "SELECT scope, COUNT(*) count FROM quarantine_rate_limit_identities GROUP BY scope"
        )
    return (
        {row["bucket"]: int(row["count"]) for row in events},
        {row["scope"]: int(row["count"]) for row in identities},
    )


async def reset(repository: QuarantineRepository, limiter: RateLimiter) -> None:
    async with repository.db.transaction(capacity_lock=True) as tx:
        await tx.execute("DELETE FROM quarantine_items")
        await tx.execute("DELETE FROM quarantine_events")
        if isinstance(limiter, PostgresRateLimiter):
            await tx.execute("DELETE FROM quarantine_rate_limit_events")
            await tx.execute("DELETE FROM quarantine_rate_limit_identities")
    if isinstance(limiter, InMemoryRateLimiter):
        limiter.events.clear()
        limiter.distinct.clear()


async def verify_admission(url: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    async with AsyncExitStack() as resources:
        backend = await create_backend(url)
        resources.push_async_callback(backend.database.close)
        if backend.rate_limit_database is not None:
            resources.push_async_callback(backend.rate_limit_database.close)
        second = await create_backend(url)
        resources.push_async_callback(second.database.close)
        if second.rate_limit_database is not None:
            resources.push_async_callback(second.rate_limit_database.close)
        repository = QuarantineRepository(backend.database)
        other = QuarantineRepository(second.database)
        limiter = backend.rate_limiter
        for legacy_first in (True, False):
            await reset(repository, limiter)
            await verify_memory_generation_race(
                repository,
                other,
                limiter,
                second.rate_limiter,
                pem,
                private_pem,
                legacy_first=legacy_first,
            )
        for kind in ("retain_request", "recall_request", "recalled_memory", "security_event"):
            for expire in (False, True):
                await reset(repository, limiter)
                limits = QuarantineLimits(item_ttl_days=1, distinct_family_limit_max=10)
                store = QuarantineStore(pem, repository, limits, limiter)
                value = admission(kind)
                original = await store.put(value)
                paused = PausedStore(pem, repository, limits, limiter)
                pending = asyncio.create_task(paused.put({**value, "timestamp": LATER}))
                await asyncio.wait_for(paused.wrapping.wait(), 5)
                if expire:
                    assert await sweep_expired(other, LATER) == 1
                else:
                    assert (await cleanup(other, "pending", None, None, 1, AT))["count"] == 1
                assert await other.get(original["quarantine_id"]) is None
                paused.resume.set()
                recreated = await asyncio.wait_for(pending, 5)
                assert recreated["quarantine_id"] == original["quarantine_id"]
                current = await repository.get(original["quarantine_id"])
                assert current and current["requarantine_count"] == 0
                events, families = await budget(limiter)
                assert events == {
                    "quarantine-writes:writer:main": 2,
                    "quarantine-writes": 2,
                    "quarantine-requarantine-ops": 1,
                }, events
                assert all(count == 1 for count in families.values()), families

        # A caller can mutate nested payload during wrapping. The recreation's
        # family must match the prepared ciphertext, which still contains "x".
        await reset(repository, limiter)
        immutable_limits = QuarantineLimits(distinct_family_limit_max=1)
        mutable = admission()
        store = QuarantineStore(pem, repository, immutable_limits, limiter)
        original = await store.put(mutable)
        paused = PausedStore(pem, repository, immutable_limits, limiter)
        pending = asyncio.create_task(paused.put(mutable))
        await asyncio.wait_for(paused.wrapping.wait(), 5)
        await cleanup(other, "pending", None, None, 1, AT)
        mutable["payload"]["items"][0]["content"] = "mutated during wrapping"
        paused.resume.set()
        assert await asyncio.wait_for(pending, 5) == original
        events, families = await budget(limiter)
        assert events["quarantine-writes"] == 2
        assert families == {"quarantine-request-family:retain_request:suspicious_content:main": 1}

        await reset(repository, limiter)
        auth_value = {**admission("security_event"), "reason": "auth_failed", "writerId": None}
        store = QuarantineStore(pem, repository, QuarantineLimits(), limiter)
        await store.put(auth_value)
        paused = PausedStore(pem, repository, QuarantineLimits(), limiter)
        pending = asyncio.create_task(paused.put(auth_value))
        await asyncio.wait_for(paused.wrapping.wait(), 5)
        await cleanup(other, "pending", None, None, 1, AT)
        paused.resume.set()
        await asyncio.wait_for(pending, 5)
        assert await budget(limiter) == (
            {"quarantine-writes:auth-audit": 2, "quarantine-requarantine-ops:auth-audit": 1},
            {},
        )

        for dimension in ("writer", "global", "family"):
            await reset(repository, limiter)
            limits = QuarantineLimits(
                rate_limit_max=1 if dimension == "writer" else 10,
                rate_limit_global_max=1 if dimension == "global" else 10,
                distinct_family_limit_max=1 if dimension == "family" else 10,
            )
            store = QuarantineStore(pem, repository, limits, limiter)
            value = admission()
            original = await store.put(value)
            paused = PausedStore(pem, repository, limits, limiter)
            changed = {**value, "payload": {"items": [{"content": "changed"}]}}
            pending = asyncio.create_task(paused.put(changed))
            await asyncio.wait_for(paused.wrapping.wait(), 5)
            await cleanup(other, "pending", None, None, 1, AT)
            expected = await budget(limiter)
            paused.resume.set()
            try:
                await asyncio.wait_for(pending, 5)
            except HttpError as error:
                assert error.code == "quarantine_rate_limited"
            else:
                raise AssertionError(f"recreation bypassed {dimension} admission limit")
            assert await repository.get(original["quarantine_id"]) is None
            assert await budget(limiter) == expected
            async with repository.db.transaction() as tx:
                assert await tx.fetchone("SELECT COUNT(*) count FROM quarantine_items") == {
                    "count": 0
                }
                assert await tx.fetchone("SELECT COUNT(*) count FROM quarantine_events") == {
                    "count": 2
                }

        # Retained expired rows are refreshes; cancelled wraps retain early attempts.
        await reset(repository, limiter)
        limits = QuarantineLimits(rate_limit_max=1, item_ttl_days=1)
        value = admission()
        store = QuarantineStore(pem, repository, limits, limiter)
        original = await store.put(value)
        await store.put({**value, "timestamp": LATER})
        events, _ = await budget(limiter)
        assert events["quarantine-writes"] == 1
        assert events["quarantine-requarantine-ops"] == 1
        paused = PausedStore(pem, repository, limits, limiter)
        pending = asyncio.create_task(paused.put(value))
        await asyncio.wait_for(paused.wrapping.wait(), 5)
        pending.cancel()
        try:
            await pending
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("wrap cancellation was swallowed")
        events, _ = await budget(limiter)
        assert events["quarantine-requarantine-ops"] == 2
        assert (await repository.get(original["quarantine_id"]))["requarantine_count"] == 1
        assert await asyncio.wait_for(store.put(value), 5) == original

        # Final classification retains the row lock against concurrent cleanup.
        await reset(repository, limiter)
        store = QuarantineStore(pem, repository, QuarantineLimits(), limiter)
        original = await store.put(value)
        prepared = asyncio.Event()
        finish = asyncio.Event()
        original_assert = repository._assert_capacity

        async def pause_capacity(*args: Any, **kwargs: Any) -> None:
            prepared.set()
            await finish.wait()
            await original_assert(*args, **kwargs)

        repository._assert_capacity = pause_capacity  # type: ignore[method-assign]
        pending = asyncio.create_task(store.put(value))
        await asyncio.wait_for(prepared.wait(), 5)
        deleting = asyncio.create_task(cleanup(other, "pending", None, None, 1, AT))
        done, _ = await asyncio.wait({deleting}, timeout=0.05)
        assert not done, "cleanup deleted a row after synchronized admission classification"
        finish.set()
        await asyncio.wait_for(pending, 5)
        await asyncio.wait_for(deleting, 5)
        repository._assert_capacity = original_assert  # type: ignore[method-assign]
        assert await repository.get(original["quarantine_id"]) is None
        await store.put(value)
        events, _ = await budget(limiter)
        assert events["quarantine-writes"] == 2
        assert events["quarantine-requarantine-ops"] == 1

        await reset(repository, limiter)
        original = await store.put(value)
        paused = PausedStore(pem, repository, QuarantineLimits(), limiter)
        pending = asyncio.create_task(paused.put(value))
        await asyncio.wait_for(paused.wrapping.wait(), 5)
        await claim_review(other, original["quarantine_id"], "retain_request", AT)
        paused.resume.set()
        try:
            await asyncio.wait_for(pending, 5)
        except HttpError as error:
            assert error.code == "quarantine_request_in_review"
        else:
            raise AssertionError("refresh overwrote an active review")
        assert (await repository.get(original["quarantine_id"]))["status"] == "review_in_progress"

        # A post-store outer identity failure must not undo the NEW correction.
        for error in (RuntimeError("identity completion failed"), asyncio.CancelledError()):
            await reset(repository, limiter)
            original = await store.put(value)
            paused = PausedStore(pem, repository, QuarantineLimits(), limiter)
            original_lock = limiter.with_identity_lock

            async def fail_after_store(
                identity: str,
                operation: Any,
                failure: BaseException = error,
                lock: Any = original_lock,
            ) -> Any:
                async def fail(session: Any) -> Any:
                    await operation(session)
                    raise failure

                return await lock(identity, fail)

            limiter.with_identity_lock = fail_after_store  # type: ignore[method-assign]
            pending = asyncio.create_task(paused.put(value))
            await asyncio.wait_for(paused.wrapping.wait(), 5)
            await cleanup(other, "pending", None, None, 1, AT)
            paused.resume.set()
            try:
                await asyncio.wait_for(pending, 5)
            except (RuntimeError, asyncio.CancelledError) as actual:
                assert actual is error
            else:
                raise AssertionError("identity completion failure was swallowed")
            finally:
                limiter.with_identity_lock = original_lock  # type: ignore[method-assign]
            assert await repository.get(original["quarantine_id"]) is not None
            events, _ = await budget(limiter)
            assert events == {
                "quarantine-writes:writer:main": 2,
                "quarantine-writes": 2,
                "quarantine-requarantine-ops": 1,
            }, events
            await asyncio.wait_for(store.put(value), 5)

        # Five concurrent identity corrections complete without an extra limiter lease.
        await reset(repository, limiter)
        values = [{**value, "dedupeKey": f"parallel-{index}"} for index in range(5)]
        await asyncio.gather(*(store.put(item) for item in values))
        paused_stores = [PausedStore(pem, repository, QuarantineLimits(), limiter) for _ in values]
        pending_many = [
            asyncio.create_task(s.put(v)) for s, v in zip(paused_stores, values, strict=True)
        ]
        await asyncio.wait_for(asyncio.gather(*(s.wrapping.wait() for s in paused_stores)), 5)
        await cleanup(other, "pending", None, None, 5, AT)
        for s in paused_stores:
            s.resume.set()
        await asyncio.wait_for(asyncio.gather(*pending_many), 5)
        events, families = await budget(limiter)
        assert events == {
            "quarantine-writes:writer:main": 10,
            "quarantine-writes": 10,
            "quarantine-requarantine-ops": 5,
        }, events
        assert all(count == 1 for count in families.values()), families

        await reset(repository, limiter)
        results = await asyncio.gather(*(store.put(value) for _ in range(5)))
        assert all(result == results[0] for result in results)
        row = await repository.get(results[0]["quarantine_id"])
        assert row and row["requarantine_count"] == 4
        events, _ = await budget(limiter)
        assert 1 <= events["quarantine-writes"] <= 5
        assert events["quarantine-requarantine-ops"] == 4

        # All preflight reads see absence. Only one insertion and one refresh fit
        # the final refresh budget, while all five early NEW attempts stay charged.
        await reset(repository, limiter)
        tight = QuarantineLimits(requarantine_ops_max=1)
        cohort = [PausedStore(pem, repository, tight, limiter) for _ in range(5)]
        pending_many = [asyncio.create_task(s.put(value)) for s in cohort]
        await asyncio.wait_for(asyncio.gather(*(s.wrapping.wait() for s in cohort)), 5)
        for s in cohort:
            s.resume.set()
        results = await asyncio.wait_for(asyncio.gather(*pending_many, return_exceptions=True), 5)
        successful = [result for result in results if isinstance(result, dict)]
        rejected = [result for result in results if isinstance(result, BaseException)]
        assert len(successful) == 2 and successful[0] == successful[1], results
        assert len(rejected) == 3 and all(
            isinstance(error, HttpError) and error.code == "quarantine_rate_limited"
            for error in rejected
        ), results
        row = await repository.get(successful[0]["quarantine_id"])
        assert row and row["requarantine_count"] == 1
        events, _ = await budget(limiter)
        assert events == {
            "quarantine-writes:writer:main": 5,
            "quarantine-writes": 5,
            "quarantine-requarantine-ops": 1,
        }, events

        # Roll back an item/event written after the correction, preserving the early attempt.
        for failure in (RuntimeError("insert failed"), asyncio.CancelledError()):
            await reset(repository, limiter)
            store = QuarantineStore(pem, repository, QuarantineLimits(), limiter)
            original = await store.put(value)
            paused = PausedStore(pem, repository, QuarantineLimits(), limiter)
            pending = asyncio.create_task(paused.put(value))
            await asyncio.wait_for(paused.wrapping.wait(), 5)
            await cleanup(other, "pending", None, None, 1, AT)
            before = await budget(limiter)
            original_insert = repository.insert_item

            async def fail_insert(
                tx: Any,
                item: dict[str, Any],
                error: BaseException = failure,
                insert: Any = original_insert,
            ) -> None:
                await insert(tx, item)
                raise error

            repository.insert_item = fail_insert  # type: ignore[method-assign]
            paused.resume.set()
            try:
                await asyncio.wait_for(pending, 5)
            except (RuntimeError, asyncio.CancelledError) as actual:
                assert actual is failure
            else:
                raise AssertionError("post-correction item failure was swallowed")
            finally:
                repository.insert_item = original_insert  # type: ignore[method-assign]
            assert await repository.get(original["quarantine_id"]) is None
            if isinstance(limiter, PostgresRateLimiter):
                assert await budget(limiter) == before
            events, _ = await budget(limiter)
            assert events["quarantine-requarantine-ops"] == 1
            async with repository.db.transaction() as tx:
                assert await tx.fetchone("SELECT COUNT(*) count FROM quarantine_events") == {
                    "count": 2
                }

        # Capacity failure rejects before correction on either backend, retaining early charge.
        await reset(repository, limiter)
        store = QuarantineStore(pem, repository, QuarantineLimits(), limiter)
        original = await store.put(value)
        paused = PausedStore(pem, repository, QuarantineLimits(max_pending_items=1), limiter)
        pending = asyncio.create_task(paused.put(value))
        await asyncio.wait_for(paused.wrapping.wait(), 5)
        await cleanup(other, "pending", None, None, 1, AT)
        await store.put({**value, "dedupeKey": "other"})
        before = await budget(limiter)
        paused.resume.set()
        try:
            await asyncio.wait_for(pending, 5)
        except HttpError as error:
            assert error.code == "quarantine_capacity_exceeded"
        else:
            raise AssertionError("recreation bypassed capacity")
        assert await repository.get(original["quarantine_id"]) is None
        assert (await repository.stats(AT))["pending_items"] == 1
        assert await budget(limiter) == before
        events, _ = await budget(limiter)
        assert events["quarantine-requarantine-ops"] == 1


async def main() -> None:
    configured = os.environ["QUARANTINE_DATABASE_URL"]
    if not is_postgres(configured):
        with TemporaryDirectory() as directory:
            await verify_admission(f"sqlite:{Path(directory) / 'admission.db'}")
        return
    schema = "quarantine_admission_" + uuid.uuid4().hex
    database = PostgresDatabase(configured)
    await database.initialize()
    try:
        async with database.transaction() as tx:
            await tx.execute(f"CREATE SCHEMA {schema}")
        parts = urlsplit(configured)
        query = urlencode([*parse_qsl(parts.query), ("options", f"-csearch_path={schema}")])
        try:
            await verify_admission(urlunsplit(parts._replace(query=query)))
        finally:
            async with database.transaction() as tx:
                await tx.execute(f"DROP SCHEMA {schema} CASCADE")
    finally:
        await database.close()


if __name__ == "__main__":
    asyncio.run(main())
