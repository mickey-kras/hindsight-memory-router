from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from memory_router.db import Database, Tx, create_database
from memory_router.errors import HttpError
from memory_router.human_auth_store import (
    HumanAuthStore,
    IssuedSession,
    RefreshPolicy,
    RefreshRejected,
)
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
    issued = await first.issue(
        activation_epoch=await first.require_generation(), principal_id="human-test", grants=GRANTS
    )
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
    issued = await first.issue(
        activation_epoch=await first.require_generation(), principal_id="human-test", grants=GRANTS
    )
    await set_expired(first.db, "sessions")
    assert await second.authenticate(issued.key_id, issued.token.split("_")[2]) is None


async def test_activation_blocks_stale_replica_and_never_resurrects_sessions(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second = stores
    transaction = await login(first)
    issued = await first.issue(
        activation_epoch=await first.require_generation(), principal_id="human-test", grants=GRANTS
    )
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
        first.issue(activation_epoch=1, principal_id="human-test", grants=GRANTS),
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
        issued = await first.issue(
            activation_epoch=await first.require_generation(),
            principal_id="human-test",
            grants=GRANTS,
        )
        await second.revoke(issued.key_id)
    results = await asyncio.gather(
        first.issue(
            activation_epoch=await first.require_generation(),
            principal_id="human-test",
            grants=GRANTS,
        ),
        second.issue(
            activation_epoch=await second.require_generation(),
            principal_id="human-test",
            grants=GRANTS,
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(result, HttpError) and result.status == 429 for result in results) == 1
    await set_expired(first.db, "sessions")
    await second.issue(
        activation_epoch=await second.require_generation(), principal_id="human-test", grants=GRANTS
    )


async def test_global_caps_and_prune(stores: tuple[HumanAuthStore, HumanAuthStore]) -> None:
    first, second = stores
    async with first.db.transaction() as tx:
        for index in range(1000):
            await tx.execute(
                "INSERT INTO human_auth_logins VALUES(?,?,?,?,?,?,?,?)",
                (str(index), "generation-a", 1, "s", "c", "uri", "nonce", 9_999_999_999_999),
            )
    with pytest.raises(HttpError) as full:
        await login(second)
    assert full.value.status == 429
    await set_expired(first.db, "logins")
    transaction = await login(second)
    async with first.db.transaction() as tx:
        for index in range(10_000):
            await tx.execute(
                "INSERT INTO human_auth_sessions VALUES(?,?,?,?,?,?,?,?)",
                (
                    str(index),
                    "generation-a",
                    str(index),
                    "digest",
                    "[]",
                    9_999_999_999_999,
                    1,
                    None,
                ),
            )
    with pytest.raises(HttpError) as full:
        await second.issue(
            activation_epoch=await second.require_generation(), principal_id="other", grants=GRANTS
        )
    assert full.value.status == 429
    for action in (
        login(second),
        second.claim_login(transaction, state="s" * 43, challenge="c" * 43),
    ):
        with pytest.raises(HttpError) as admission:
            await action
        assert admission.value.status == 429
    await set_expired(first.db, "sessions")
    await second.issue(
        activation_epoch=await second.require_generation(), principal_id="other", grants=GRANTS
    )


@pytest.mark.parametrize("restore_config", [False, True])
async def test_activation_invalidates_inflight_exchange(
    stores: tuple[HumanAuthStore, HumanAuthStore], restore_config: bool
) -> None:
    first, second = stores
    transaction = await login(first)
    claimed = asyncio.Event()
    provider_returned = asyncio.Event()

    async def exchange() -> None:
        binding = await first.claim_login(transaction, state="s" * 43, challenge="c" * 43)
        claimed.set()
        await provider_returned.wait()
        await first.issue(
            activation_epoch=binding.activation_epoch, principal_id="human-test", grants=GRANTS
        )

    task = asyncio.create_task(exchange())
    await claimed.wait()
    if restore_config:
        replacement = HumanAuthStore(second.db, "generation-b")
        await replacement.initialize(check_generation=False)
        await replacement.activate()
    await second.activate()
    provider_returned.set()
    with pytest.raises(HttpError) as stale:
        await task
    assert stale.value.status == 401
    async with first.db.transaction() as tx:
        assert await tx.fetchone("SELECT * FROM human_auth_sessions") is None
    fresh = await login(first)
    binding = await first.claim_login(fresh, state="s" * 43, challenge="c" * 43)
    issued = await first.issue(
        activation_epoch=binding.activation_epoch, principal_id="human-test", grants=GRANTS
    )
    assert await second.authenticate(issued.key_id, issued.token.split("_")[2]) is not None


async def test_cancel_login_removes_only_selected_transaction(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second = stores
    cancelled, retained = await login(first), await login(first)
    await second.cancel_login(cancelled)
    with pytest.raises(HttpError) as missing:
        await first.claim_login(cancelled, state="s" * 43, challenge="c" * 43)
    assert missing.value.status == 401
    await first.claim_login(retained, state="s" * 43, challenge="c" * 43)


async def test_authentication_does_not_take_allocation_lock(
    stores: tuple[HumanAuthStore, HumanAuthStore], monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = stores
    issued = await first.issue(
        activation_epoch=await first.require_generation(), principal_id="human-test", grants=GRANTS
    )
    transaction = second.db.transaction
    capacity_locks: list[bool] = []

    @asynccontextmanager
    async def observe_transaction(*, capacity_lock: bool = False) -> AsyncIterator[Tx]:
        capacity_locks.append(capacity_lock)
        async with transaction(capacity_lock=capacity_lock) as tx:
            yield tx

    monkeypatch.setattr(second.db, "transaction", observe_transaction)
    secret = issued.token.split("_")[2]
    assert await second.authenticate(issued.key_id, secret) is not None
    assert await second.authenticate(issued.key_id, "0" * 64) is None
    assert await second.authenticate("0" * 32, "0" * 64) is None
    assert capacity_locks == [False, False, False]


POLICY = RefreshPolicy(idle_ms=86_400_000, absolute_ms=604_800_000)


def _accept(_principal: str, grants: tuple[PrincipalGrant, ...]) -> tuple[PrincipalGrant, ...]:
    return grants


def _parts(token: str | None) -> tuple[str, str]:
    assert token is not None
    _, key_id, secret = token.split("_")
    return key_id, secret


async def _refreshable(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> tuple[HumanAuthStore, HumanAuthStore, IssuedSession]:
    first, second = stores
    first.refresh_policy = second.refresh_policy = POLICY
    issued = await first.issue(
        activation_epoch=await first.require_generation(), principal_id="human-test", grants=GRANTS
    )
    return first, second, issued


async def test_refresh_rotates_hashed_token_once(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second, issued = await _refreshable(stores)
    key_id, secret = _parts(issued.refresh_token)
    assert issued.refresh_token is not None and issued.refresh_token not in repr(issued)
    async with first.db.transaction() as tx:
        row = await tx.fetchone("SELECT * FROM human_auth_refresh_tokens WHERE key_id=?", (key_id,))
        assert row is not None and secret not in str(row)
        assert row["secret_digest"] == hashlib.sha256(secret.encode()).hexdigest()
    refreshed = await second.refresh(key_id, secret, _accept)
    assert refreshed.refresh_token != issued.refresh_token
    assert refreshed.principal_id == "human-test" and refreshed.grants == GRANTS
    assert await first.authenticate(*_parts(refreshed.token)) is not None
    # The superseded access token keeps only a short grace window.
    async with first.db.transaction() as tx:
        row = await tx.fetchone(
            "SELECT expires_at_ms FROM human_auth_sessions WHERE key_id=?", (issued.key_id,)
        )
        assert row is not None and int(row["expires_at_ms"]) < refreshed.expires_at * 1000


async def test_concurrent_rotation_succeeds_once_and_reuse_revokes_successor(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second, issued = await _refreshable(stores)
    key_id, secret = _parts(issued.refresh_token)
    results = await asyncio.gather(
        first.refresh(key_id, secret, _accept),
        second.refresh(key_id, secret, _accept),
        return_exceptions=True,
    )
    winners = [result for result in results if isinstance(result, IssuedSession)]
    rejected = [result for result in results if isinstance(result, RefreshRejected)]
    assert len(winners) == 1 and len(rejected) == 1 and rejected[0].reuse
    successor = winners[0]
    assert await first.authenticate(*_parts(successor.token)) is None
    assert await first.authenticate(*_parts(issued.token)) is None
    with pytest.raises(RefreshRejected) as replay:
        await first.refresh(*_parts(successor.refresh_token), _accept)
    assert not replay.value.reuse


async def test_unknown_and_wrong_secret_refresh_do_not_revoke(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second, issued = await _refreshable(stores)
    key_id, _ = _parts(issued.refresh_token)
    for attempt in ((key_id, "0" * 64), ("0" * 32, "0" * 64)):
        with pytest.raises(RefreshRejected):
            await second.refresh(*attempt, _accept)
    assert await first.authenticate(*_parts(issued.token)) is not None


@pytest.mark.parametrize("column", ["idle_expires_at_ms", "absolute_expires_at_ms"])
async def test_idle_and_absolute_expiry(
    stores: tuple[HumanAuthStore, HumanAuthStore], column: str
) -> None:
    first, second, issued = await _refreshable(stores)
    async with first.db.transaction() as tx:
        # Column names are fixed by the parametrization, never user input.
        await tx.execute(f"UPDATE human_auth_families SET {column}=1")  # noqa: S608
    with pytest.raises(RefreshRejected):
        await second.refresh(*_parts(issued.refresh_token), _accept)
    await second.prune()
    async with first.db.transaction() as tx:
        assert await tx.fetchone("SELECT * FROM human_auth_families") is None
        assert await tx.fetchone("SELECT * FROM human_auth_refresh_tokens") is None


async def test_access_and_idle_lifetimes_are_bounded_by_absolute_lifetime(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second = stores
    first.refresh_policy = RefreshPolicy(idle_ms=3_600_000, absolute_ms=1_800_000)
    issued = await first.issue(
        activation_epoch=await first.require_generation(), principal_id="human-test", grants=GRANTS
    )
    async with first.db.transaction() as tx:
        row = await tx.fetchone("SELECT * FROM human_auth_families")
        assert row is not None
        assert row["idle_expires_at_ms"] == row["absolute_expires_at_ms"]
        assert issued.expires_at == int(row["absolute_expires_at_ms"]) // 1000


async def test_lost_permission_revokes_session(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second, issued = await _refreshable(stores)
    with pytest.raises(RefreshRejected) as rejected:
        await second.refresh(*_parts(issued.refresh_token), lambda _principal, _grants: None)
    assert not rejected.value.reuse
    assert await first.authenticate(*_parts(issued.token)) is None
    with pytest.raises(RefreshRejected):
        await first.refresh(*_parts(issued.refresh_token), _accept)


async def test_sign_out_after_access_expiry_and_harness_isolation(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second, signed_out = await _refreshable(stores)
    other = await first.issue(
        activation_epoch=await first.require_generation(), principal_id="human-test", grants=GRANTS
    )
    await set_expired(first.db, "sessions")
    assert await second.sign_out_refresh(*_parts(signed_out.refresh_token))
    assert not await second.sign_out_refresh("0" * 32, "0" * 64)
    with pytest.raises(RefreshRejected):
        await first.refresh(*_parts(signed_out.refresh_token), _accept)
    refreshed = await first.refresh(*_parts(other.refresh_token), _accept)
    assert await second.authenticate(*_parts(refreshed.token)) is not None


@pytest.mark.parametrize("credential", ["access", "refresh"])
async def test_operator_revocation_invalidates_whole_session(
    stores: tuple[HumanAuthStore, HumanAuthStore], credential: str
) -> None:
    first, second, issued = await _refreshable(stores)
    refreshed = await first.refresh(*_parts(issued.refresh_token), _accept)
    other = await first.issue(
        activation_epoch=await first.require_generation(), principal_id="human-test", grants=GRANTS
    )
    target = issued.key_id if credential == "access" else _parts(refreshed.refresh_token)[0]
    await second.revoke(target)
    for token in (issued.token, refreshed.token):
        assert await first.authenticate(*_parts(token)) is None
    with pytest.raises(RefreshRejected):
        await first.refresh(*_parts(refreshed.refresh_token), _accept)
    assert await first.authenticate(*_parts(other.token)) is not None


async def test_activation_revokes_refreshable_sessions_and_disabled_policy_rejects(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second, issued = await _refreshable(stores)
    await second.activate()
    with pytest.raises(RefreshRejected):
        await first.refresh(*_parts(issued.refresh_token), _accept)
    first.refresh_policy = None
    with pytest.raises(RefreshRejected):
        await first.refresh(*_parts(issued.refresh_token), _accept)
    assert (
        await first.issue(
            activation_epoch=await first.require_generation(),
            principal_id="human-test",
            grants=GRANTS,
        )
    ).refresh_token is None


async def test_refresh_sessions_count_against_per_principal_cap(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second, issued = await _refreshable(stores)
    for _ in range(19):
        await first.issue(
            activation_epoch=await first.require_generation(),
            principal_id="human-test",
            grants=GRANTS,
        )
    await set_expired(first.db, "sessions")
    with pytest.raises(HttpError) as full:
        await second.issue(
            activation_epoch=await second.require_generation(),
            principal_id="human-test",
            grants=GRANTS,
        )
    assert full.value.status == 429
    # A revoked session still counts, but only for one access lifetime.
    await second.sign_out_refresh(*_parts(issued.refresh_token))
    async with first.db.transaction() as tx:
        row = await tx.fetchone(
            "SELECT idle_expires_at_ms FROM human_auth_families WHERE revoked=1"
        )
        assert row is not None and int(row["idle_expires_at_ms"]) <= time.time() * 1000 + 3_600_000


async def test_initialize_migrates_sessions_without_family_column(tmp_path: Path) -> None:
    db = await create_database(f"sqlite:{tmp_path / 'legacy.db'}")
    try:
        async with db.transaction() as tx:
            await tx.execute(
                "CREATE TABLE human_auth_sessions (key_id TEXT PRIMARY KEY, generation TEXT NOT NULL, "
                "principal_id TEXT NOT NULL, secret_digest TEXT NOT NULL, grants TEXT NOT NULL, "
                "expires_at_ms BIGINT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)"
            )
        store = HumanAuthStore(db, "generation-a", POLICY)
        await store.initialize()
        issued = await store.issue(
            activation_epoch=await store.require_generation(),
            principal_id="human-test",
            grants=GRANTS,
        )
        assert await store.authenticate(*_parts(issued.token)) is not None
    finally:
        await db.close()


async def test_operator_revokes_refreshed_session_by_pruned_access_key(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second, issued = await _refreshable(stores)
    refreshed = await first.refresh(*_parts(issued.refresh_token), _accept)
    # The superseded access row is pruned once its grace window ends.
    async with first.db.transaction() as tx:
        await tx.execute(
            "UPDATE human_auth_sessions SET expires_at_ms=1 WHERE key_id=?", (issued.key_id,)
        )
    await second.prune()
    assert await second.revoke(issued.key_id)
    assert await first.authenticate(*_parts(refreshed.token)) is None
    with pytest.raises(RefreshRejected):
        await first.refresh(*_parts(refreshed.refresh_token), _accept)
    assert not await second.revoke("0" * 32)


async def test_activation_bounds_revoked_session_retention(
    stores: tuple[HumanAuthStore, HumanAuthStore],
) -> None:
    first, second, _ = await _refreshable(stores)
    await second.activate()
    async with first.db.transaction() as tx:
        row = await tx.fetchone("SELECT revoked, idle_expires_at_ms FROM human_auth_families")
    assert row is not None and int(row["revoked"]) == 1
    assert int(row["idle_expires_at_ms"]) <= time.time() * 1000 + 3_600_000
