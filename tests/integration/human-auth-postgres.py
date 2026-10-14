from __future__ import annotations

import asyncio
import os

from memory_router.db import create_database
from memory_router.errors import HttpError
from memory_router.human_auth_store import HumanAuthStore
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
        assert await second.authenticate(issued.key_id, secret) is not None
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
