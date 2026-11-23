from __future__ import annotations

import asyncio
import os

from memory_router.db import create_database
from memory_router.errors import HttpError
from memory_router.human_auth_store import (
    HumanAuthStore,
    IssuedSession,
    RefreshPolicy,
    RefreshRejected,
)
from memory_router.principals import PrincipalGrant


async def verify() -> None:
    url = os.environ["QUARANTINE_DATABASE_URL"]
    first_db, second_db = await create_database(url), await create_database(url)
    try:
        assert first_db.dialect == second_db.dialect == "postgres"
        first, second = HumanAuthStore(first_db, "smoke-a"), HumanAuthStore(second_db, "smoke-a")
        await first.initialize()
        await second.initialize()
        transaction = await first.create_login(
            state="s" * 43,
            challenge="c" * 43,
            redirect_uri="http://127.0.0.1:1234/callback",
            nonce="n" * 43,
        )
        results = await asyncio.gather(
            first.claim_login(transaction, state="s" * 43, challenge="c" * 43),
            second.claim_login(transaction, state="s" * 43, challenge="c" * 43),
            return_exceptions=True,
        )
        assert (
            sum(isinstance(result, HttpError) and result.status == 401 for result in results) == 1
        )
        assert sum(not isinstance(result, BaseException) for result in results) == 1
        grants = (PrincipalGrant(bank="smoke", scopes=["memory.recall"]),)
        issued = await first.issue(
            activation_epoch=await first.require_generation(),
            principal_id="human-smoke",
            grants=grants,
        )
        secret = issued.token.split("_")[2]
        async with first_db.transaction(capacity_lock=True):
            async with asyncio.timeout(5):
                assert await second.authenticate(issued.key_id, secret) is not None
                assert await second.authenticate(issued.key_id, "0" * 64) is None
                assert await second.authenticate("0" * 32, "0" * 64) is None
        await first.revoke(issued.key_id)
        assert await second.authenticate(issued.key_id, secret) is None
        # Unexpired revoked sessions still count, including across two independent pools.
        for _ in range(18):
            issued = await first.issue(
                activation_epoch=await first.require_generation(),
                principal_id="human-smoke",
                grants=grants,
            )
            await second.revoke(issued.key_id)
        results = await asyncio.gather(
            first.issue(
                activation_epoch=await first.require_generation(),
                principal_id="human-smoke",
                grants=grants,
            ),
            second.issue(
                activation_epoch=await second.require_generation(),
                principal_id="human-smoke",
                grants=grants,
            ),
            return_exceptions=True,
        )
        assert (
            sum(isinstance(result, HttpError) and result.status == 429 for result in results) == 1
        )
        # Concurrent rotation across independent pools succeeds once; reuse revokes the successor.
        first.refresh_policy = second.refresh_policy = RefreshPolicy(3_600_000, 86_400_000)
        refreshable = await first.issue(
            activation_epoch=await first.require_generation(),
            principal_id="human-refresh",
            grants=grants,
        )
        assert refreshable.refresh_token is not None
        _, refresh_key, refresh_secret = refreshable.refresh_token.split("_")
        rotated = await asyncio.gather(
            first.refresh(refresh_key, refresh_secret, lambda _principal, ceiling: ceiling),
            second.refresh(refresh_key, refresh_secret, lambda _principal, ceiling: ceiling),
            return_exceptions=True,
        )
        winners = [result for result in rotated if isinstance(result, IssuedSession)]
        assert len(winners) == 1
        assert sum(isinstance(result, RefreshRejected) and result.reuse for result in rotated) == 1
        _, successor_key, successor_secret = winners[0].token.split("_")
        assert await second.authenticate(successor_key, successor_secret) is None
        # Operators can revoke a refreshed session by an access key ID whose row was pruned.
        live = await first.issue(
            activation_epoch=await first.require_generation(),
            principal_id="human-refresh",
            grants=grants,
        )
        assert live.refresh_token is not None
        renewed = await first.refresh(
            *live.refresh_token.split("_")[1:], lambda _principal, ceiling: ceiling
        )
        async with first_db.transaction() as tx:
            await tx.execute(
                "UPDATE human_auth_sessions SET expires_at_ms=1 WHERE key_id=?", (live.key_id,)
            )
        await second.prune()
        assert await second.revoke(live.key_id)
        assert await first.authenticate(*renewed.token.split("_")[1:]) is None
        assert not await second.revoke("0" * 32)
        replacement = HumanAuthStore(second_db, "smoke-b")
        await replacement.initialize(check_generation=False)
        await replacement.activate()
        for operation in (
            first.require_generation(),
            first.issue(activation_epoch=1, principal_id="human-other", grants=grants),
            first.authenticate(issued.key_id, secret),
        ):
            try:
                await operation
            except HttpError as error:
                assert error.status == 503
            else:
                raise AssertionError("stale policy accepted")
    finally:
        await first_db.close()
        await second_db.close()


asyncio.run(verify())
