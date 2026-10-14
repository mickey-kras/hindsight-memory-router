from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from memory_router.db import Database, create_database
from memory_router.errors import HttpError
from memory_router.human_auth_store import HumanAuthStore
from memory_router.principals import PrincipalGrant

GRANTS = (
    PrincipalGrant(bank="alpha", scopes=["memory.recall"]),
    PrincipalGrant(bank="beta", scopes=["memory.retain"]),
)


@pytest.fixture
async def stores(tmp_path: Path) -> AsyncIterator[tuple[HumanAuthStore, HumanAuthStore]]:
    path = f"sqlite:{tmp_path / 'human.db'}"
    first = await create_database(path)
    second = await create_database(path)
    try:
        stores = (HumanAuthStore(first, "generation-a"), HumanAuthStore(second, "generation-a"))
        for store in stores:
            await store.initialize()
        yield stores
    finally:
        await first.close()
        await second.close()


async def login(store: HumanAuthStore) -> str:
    return await store.create_login(
        state="s" * 43,
        challenge="c" * 43,
        redirect_uri="http://127.0.0.1:1234/callback",
        nonce="n" * 43,
    )


async def set_expired(db: Database, table: str) -> None:
    # Table names are fixed by each test, never user input.
    async with db.transaction() as tx:
        if table == "logins":
            await tx.execute("UPDATE human_auth_logins SET expires_at_ms=0")
        else:
            await tx.execute("UPDATE human_auth_sessions SET expires_at_ms=0")


async def test_claim_commits_once_across_connections(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second = stores
    transaction = await login(first)
    results = await asyncio.gather(
        first.claim_login(transaction, state="s" * 43, challenge="c" * 43),
        second.claim_login(transaction, state="s" * 43, challenge="c" * 43),
        return_exceptions=True,
    )
    assert sum(isinstance(result, HttpError) and result.status == 401 for result in results) == 1
    assert sum(not isinstance(result, BaseException) for result in results) == 1


async def test_claim_survives_provider_failure_and_cancellation(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second = stores
    transaction = await login(first)
    claimed = asyncio.Event()

    async def exchange() -> None:
        await first.claim_login(transaction, state="s" * 43, challenge="c" * 43)
        claimed.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(exchange())
    await claimed.wait()
    # No DB lock remains while the provider request is pending.
    await asyncio.wait_for(second.require_generation(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(HttpError) as rejected:
        await second.claim_login(transaction, state="s" * 43, challenge="c" * 43)
    assert rejected.value.status == 401


@pytest.mark.parametrize("state,challenge", [("x" * 43, "c" * 43), ("s" * 43, "x" * 43)])
async def test_bound_fields_and_expiry(
    stores: tuple[HumanAuthStore, HumanAuthStore], state: str, challenge: str
) -> None:
    first, second = stores
    transaction = await login(first)
    with pytest.raises(HttpError):
        await second.claim_login(transaction, state=state, challenge=challenge)
    await set_expired(first.db, "logins")
    with pytest.raises(HttpError):
        await second.claim_login(transaction, state="s" * 43, challenge="c" * 43)
    await second.prune()
    async with first.db.transaction() as tx:
        assert await tx.fetchone("SELECT * FROM human_auth_logins") is None


async def test_sessions_digest_grant_pairs_revocation_and_expiry(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second = stores
    issued = await first.issue(principal_id="human-test", grants=GRANTS)
    prefix, key_id, secret = issued.token.split("_")
    assert prefix == "mrh" and len(key_id) == 32 and len(secret) == 64
    assert secret not in repr(issued)
    async with first.db.transaction() as tx:
        row = await tx.fetchone("SELECT * FROM human_auth_sessions WHERE key_id=?", (key_id,))
        assert row is not None
        assert secret not in str(row)
        assert row["secret_digest"] == hashlib.sha256(secret.encode()).hexdigest()
    session = await second.authenticate(key_id, secret)
    assert session is not None and session.grants == GRANTS
    assert await second.authenticate(key_id, "wrong") is None
    assert await second.authenticate("unknown", secret) is None
    await first.revoke(key_id)
    assert await second.authenticate(key_id, secret) is None
    issued = await first.issue(principal_id="human-test", grants=GRANTS)
    await set_expired(first.db, "sessions")
    assert await second.authenticate(issued.key_id, issued.token.split("_")[2]) is None


async def test_activation_blocks_stale_replica_and_never_resurrects_sessions(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second = stores
    transaction = await login(first)
    issued = await first.issue(principal_id="human-test", grants=GRANTS)
    new = HumanAuthStore(second.db, "generation-b")
    with pytest.raises(HttpError) as rejected:
        await new.initialize()
    assert rejected.value.status == 503
    await first.require_generation()
    await new.initialize(check_generation=False)
    await new.activate()
    for action in (
        first.require_generation(),
        login(first),
        first.claim_login(transaction, state="s" * 43, challenge="c" * 43),
        first.issue(principal_id="human-test", grants=GRANTS),
        first.authenticate(issued.key_id, issued.token.split("_")[2]),
    ):
        with pytest.raises(HttpError) as stale:
            await action
        assert stale.value.status == 503
    await first.activate()
    assert await first.authenticate(issued.key_id, issued.token.split("_")[2]) is None
    with pytest.raises(HttpError):
        await first.claim_login(transaction, state="s" * 43, challenge="c" * 43)


async def test_revocation_cannot_bypass_per_principal_cap(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second = stores
    for _ in range(19):
        issued = await first.issue(principal_id="human-test", grants=GRANTS)
        await second.revoke(issued.key_id)
    results = await asyncio.gather(
        first.issue(principal_id="human-test", grants=GRANTS),
        second.issue(principal_id="human-test", grants=GRANTS),
        return_exceptions=True,
    )
    assert sum(isinstance(result, HttpError) and result.status == 429 for result in results) == 1
    await set_expired(first.db, "sessions")
    await second.issue(principal_id="human-test", grants=GRANTS)


async def test_global_caps_and_prune(stores: tuple[HumanAuthStore, HumanAuthStore]) -> None:
    first, second = stores
    async with first.db.transaction() as tx:
        for index in range(1000):
            await tx.execute(
                "INSERT INTO human_auth_logins VALUES(?,?,?,?,?,?,?)",
                (str(index), "generation-a", "s", "c", "uri", "nonce", 9_999_999_999_999),
            )
    with pytest.raises(HttpError) as full:
        await login(second)
    assert full.value.status == 429
    await set_expired(first.db, "logins")
    transaction = await login(second)
    async with first.db.transaction() as tx:
        for index in range(10_000):
            await tx.execute(
                "INSERT INTO human_auth_sessions VALUES(?,?,?,?,?,?,?)",
                (str(index), "generation-a", str(index), "digest", "[]", 9_999_999_999_999, 1),
            )
    with pytest.raises(HttpError) as full:
        await second.issue(principal_id="other", grants=GRANTS)
    assert full.value.status == 429
    for action in (
        login(second),
        second.claim_login(transaction, state="s" * 43, challenge="c" * 43),
    ):
        with pytest.raises(HttpError) as admission:
            await action
        assert admission.value.status == 429
    await set_expired(first.db, "sessions")
    await second.issue(principal_id="other", grants=GRANTS)
