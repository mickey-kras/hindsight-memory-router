from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from memory_router.auth import AuthFailureAuditor
from memory_router.db import create_database
from memory_router.errors import HttpError
from memory_router.maintenance import cleanup, preview_cleanup
from memory_router.openclaw import OpenClawFacade
from memory_router.policy import RouterPolicy
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore
from memory_router.rate_limit import InMemoryRateLimiter
from memory_router.repository import QuarantineRepository
from tests.test_quarantine_store import public_key

AT = "2026-09-22T00:00:00.000Z"


def event(key: str, writer: str | None = "alice", bank: str | None = "alpha") -> dict[str, Any]:
    return {
        "timestamp": AT,
        "kind": "security_event",
        "reason": "denied_endpoint",
        "writerId": writer,
        "bankId": bank,
        "dedupeKey": key,
        "payload": {"path": key},
    }


@pytest.fixture
async def repository(tmp_path: Path) -> QuarantineRepository:
    database = await create_database(f"sqlite:{tmp_path / 'audit.db'}")
    try:
        yield QuarantineRepository(database)
    finally:
        await database.close()


def make_store(repository: QuarantineRepository, **limits: int) -> QuarantineStore:
    return QuarantineStore(
        public_key(),
        repository,
        QuarantineLimits(rate_limit_max=0, **limits),
        InMemoryRateLimiter(),
    )


@pytest.mark.asyncio
async def test_facade_audit_junk_cannot_consume_another_principals_capacity(
    repository: QuarantineRepository, caplog: pytest.LogCaptureFixture
) -> None:
    store = make_store(
        repository,
        max_pending_items=4,
        max_pending_items_per_writer=1,
        max_pending_items_per_bank=1,
    )
    policy = RouterPolicy(None, None, None, store, repository)
    facade = OpenClawFacade(policy)
    for padding in range(4):
        await facade._audit("alice", "denied_endpoint", {"junk": padding}, None, bank_id="alpha")
    assert (await repository.stats(AT))["pending_items"] == 1
    assert "openclaw_security_audit_failed" in caplog.text
    await store.put(event("independent", "bob", "beta"))
    assert (await repository.stats(AT))["pending_items"] == 2


@pytest.mark.asyncio
async def test_event_refresh_keeps_exact_principal_and_bank_scopes(
    repository: QuarantineRepository,
) -> None:
    store = make_store(repository, max_pending_items_per_writer=2, max_pending_items_per_bank=2)
    original = await store.put(event("same"))
    assert await store.put(event("same")) == original
    second_bank = await store.put(event("same", bank="Alpha"))
    second_writer = await store.put(event("same", writer="bob"))
    assert len({item["quarantine_id"] for item in (original, second_bank, second_writer)}) == 3
    row = await repository.get(original["quarantine_id"])
    assert row and row["writer_id"] == "alice" and row["bank_id"] == "alpha"
    assert row["requarantine_count"] == 1
    with pytest.raises(HttpError) as full:
        await store.put(event("another", writer="carol"))
    assert full.value.code == "quarantine_bank_capacity_exceeded"
    with pytest.raises(HttpError) as writer_full:
        await store.put(event("another", bank="beta"))
    assert writer_full.value.code == "quarantine_writer_capacity_exceeded"


@pytest.mark.asyncio
async def test_anonymous_auth_exemption_does_not_apply_to_attributed_events(
    repository: QuarantineRepository,
) -> None:
    store = make_store(repository, max_pending_items_per_writer=1)
    auditor = AuthFailureAuditor(store)
    await auditor.persist("router")
    await auditor.persist("admin")
    await store.put({**event("one"), "reason": "auth_failed"})
    with pytest.raises(HttpError) as attributed:
        await store.put({**event("two"), "reason": "auth_failed"})
    assert attributed.value.code == "quarantine_writer_capacity_exceeded"
    with pytest.raises(HttpError) as anonymous:
        await store.put(event("anonymous-denied", None, None))
    assert anonymous.value.code == "quarantine_writer_capacity_exceeded"


@pytest.mark.asyncio
async def test_global_identity_admission_is_atomic_and_survives_restart(tmp_path: Path) -> None:
    url = f"sqlite:{tmp_path / 'shared.db'}"
    databases = [await create_database(url), await create_database(url)]
    stores = [
        make_store(QuarantineRepository(db), max_pending_items_per_writer=0) for db in databases
    ]
    try:
        outcomes = await asyncio.gather(
            *(stores[index % 2].put(event(str(index))) for index in range(70)),
            return_exceptions=True,
        )
        failures = [outcome for outcome in outcomes if isinstance(outcome, BaseException)]
        assert len(failures) == 6
        assert all(
            isinstance(error, HttpError)
            and error.status == 507
            and error.code == "quarantine_security_event_capacity_exceeded"
            for error in failures
        )
    finally:
        await asyncio.gather(*(database.close() for database in databases))

    database = await create_database(url)
    try:
        store = make_store(QuarantineRepository(database), max_pending_items_per_writer=0)
        with pytest.raises(HttpError) as full:
            await store.put(event("after-restart"))
        assert full.value.code == "quarantine_security_event_capacity_exceeded"
        await store.put(event("0"))
        selection = await preview_cleanup(store.repository, "all", None, None)
        assert selection["count"] == 64
        await cleanup(store.repository, "all", None, None, selection["count"], AT)
        await store.put(event("after-cleanup"))
        assert (await store.repository.stats(AT))["total_items"] == 1
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_security_event_without_producer_key_is_still_scoped_and_deduplicated(
    repository: QuarantineRepository,
) -> None:
    store = make_store(repository)
    anonymous = event("payload", None, None)
    anonymous.pop("dedupeKey")
    original = await store.put(anonymous)
    repeated = await store.put(anonymous)
    attributed = await store.put({**anonymous, "writerId": "anonymous"})
    assert original == repeated
    assert original["quarantine_id"] != attributed["quarantine_id"]
