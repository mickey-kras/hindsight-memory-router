from __future__ import annotations

import asyncio
import time
from collections import Counter
from types import SimpleNamespace

import httpx
import pytest
from joserfc.jwk import RSAKey

from memory_router import human_oidc
from memory_router.errors import HttpError
from memory_router.human_auth_config import HumanAuthConfig
from memory_router.human_oidc import (
    KEY_REFRESH_INTERVAL_SECONDS,
    KEYS_TTL_SECONDS,
    METADATA_TTL_SECONDS,
    HumanOidc,
)
from tests.test_human_auth import CHALLENGE, REDIRECT, STATE, VERIFIER, Provider

DISCOVERY = "/.well-known/openid-configuration"
NONCE = "n" * 43


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class CountingProvider(Provider):
    def __init__(self) -> None:
        super().__init__()
        self.nonce = NONCE
        self.published: RSAKey | None = None
        self.unavailable: set[str] = set()
        self.release: asyncio.Event | None = None

    def count(self) -> Counter[str]:
        return Counter(call.url.path for call in self.calls)

    def rotate(self, *, publish: bool) -> None:
        previous = self.key
        self.key = RSAKey.generate_key(2048)
        self.key.ensure_kid()
        self.published = None if publish else previous

    async def handle(self, incoming: httpx.Request) -> httpx.Response:
        if self.release is not None and incoming.url.path != "/token":
            await self.release.wait()
        if incoming.url.path in self.unavailable:
            self.calls.append(incoming)
            return httpx.Response(503)
        if incoming.url.path == "/jwks" and self.published is not None:
            self.calls.append(incoming)
            return httpx.Response(200, json={"keys": [self.published.as_dict(private=False)]})
        return self.respond(incoming)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    clock = Clock()
    # Replace only this module's clock. The event loop keeps the real one.
    monkeypatch.setattr(
        human_oidc, "time", SimpleNamespace(monotonic=clock.monotonic, time=time.time)
    )
    return clock


@pytest.fixture
def provider() -> CountingProvider:
    return CountingProvider()


@pytest.fixture
async def oidc(provider: CountingProvider, clock: Clock) -> HumanOidc:
    config = HumanAuthConfig(
        router_url="https://router.example",
        issuer="https://id.example",
        client_id="coding-agent",
        subjects={"subject-1": "human-test"},
    )
    return HumanOidc(config, httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)))


async def login(oidc: HumanOidc) -> str:
    await oidc.authorization_url(
        redirect_uri=REDIRECT, state=STATE, challenge=CHALLENGE, nonce=NONCE
    )
    return await oidc.identity(
        code="authorization-code", verifier=VERIFIER, redirect_uri=REDIRECT, nonce=NONCE
    )


async def test_cold_login_fetches_each_document_once_and_warm_login_only_the_token(
    oidc: HumanOidc, provider: CountingProvider
) -> None:
    assert await login(oidc) == "subject-1"
    assert provider.count() == {DISCOVERY: 1, "/token": 1, "/jwks": 1}

    assert await login(oidc) == "subject-1"
    assert provider.count() == {DISCOVERY: 1, "/token": 2, "/jwks": 1}


async def test_concurrent_cold_logins_share_discovery_and_key_fetches(
    oidc: HumanOidc, provider: CountingProvider
) -> None:
    provider.release = asyncio.Event()
    logins = [asyncio.create_task(login(oidc)) for _ in range(5)]
    await asyncio.sleep(0.05)
    provider.release.set()

    assert await asyncio.gather(*logins) == ["subject-1"] * 5
    assert provider.count() == {DISCOVERY: 1, "/token": 5, "/jwks": 1}


async def test_cancelled_login_does_not_cancel_the_shared_fetch(
    oidc: HumanOidc, provider: CountingProvider
) -> None:
    provider.release = asyncio.Event()
    first = asyncio.create_task(login(oidc))
    second = asyncio.create_task(login(oidc))
    await asyncio.sleep(0.05)
    first.cancel()
    provider.release.set()

    assert await second == "subject-1"
    assert provider.count()[DISCOVERY] == 1


async def test_expired_documents_are_fetched_again(
    oidc: HumanOidc, provider: CountingProvider, clock: Clock
) -> None:
    await login(oidc)
    clock.now += max(METADATA_TTL_SECONDS, KEYS_TTL_SECONDS) - 1
    await login(oidc)
    assert provider.count() == {DISCOVERY: 1, "/token": 2, "/jwks": 1}

    clock.now += 1
    await login(oidc)
    assert provider.count() == {DISCOVERY: 2, "/token": 3, "/jwks": 2}


async def test_signing_key_rollover_refreshes_keys_once(
    oidc: HumanOidc, provider: CountingProvider, clock: Clock
) -> None:
    await login(oidc)
    provider.rotate(publish=True)
    clock.now += KEY_REFRESH_INTERVAL_SECONDS

    assert await login(oidc) == "subject-1"
    assert await login(oidc) == "subject-1"
    assert provider.count() == {DISCOVERY: 1, "/token": 3, "/jwks": 2}


async def test_repeated_unknown_key_ids_fail_with_rate_limited_refresh(
    oidc: HumanOidc, provider: CountingProvider, clock: Clock
) -> None:
    await login(oidc)
    provider.rotate(publish=False)

    for _ in range(3):
        with pytest.raises(HttpError) as failure:
            await login(oidc)
        assert (failure.value.status, failure.value.code) == (401, "human_login_failed")
    assert provider.count()["/jwks"] == 1

    clock.now += KEY_REFRESH_INTERVAL_SECONDS
    for _ in range(3):
        with pytest.raises(HttpError) as failure:
            await login(oidc)
        assert failure.value.status == 401
    assert provider.count()["/jwks"] == 2


async def test_provider_outage_fails_only_after_expiry_and_is_not_cached(
    oidc: HumanOidc, provider: CountingProvider, clock: Clock
) -> None:
    await login(oidc)
    provider.unavailable = {DISCOVERY, "/jwks"}

    assert await login(oidc) == "subject-1"

    clock.now += max(METADATA_TTL_SECONDS, KEYS_TTL_SECONDS)
    with pytest.raises(HttpError) as failure:
        await login(oidc)
    assert (failure.value.status, failure.value.code) == (503, "human_identity_unavailable")

    provider.unavailable = set()
    assert await login(oidc) == "subject-1"


async def test_failed_rollover_refresh_is_rate_limited(
    oidc: HumanOidc, provider: CountingProvider, clock: Clock
) -> None:
    await login(oidc)
    provider.rotate(publish=True)
    provider.unavailable = {"/jwks"}
    clock.now += KEY_REFRESH_INTERVAL_SECONDS

    with pytest.raises(HttpError) as failure:
        await login(oidc)
    assert (failure.value.status, failure.value.code) == (503, "human_identity_unavailable")
    for _ in range(3):
        with pytest.raises(HttpError) as failure:
            await login(oidc)
        assert (failure.value.status, failure.value.code) == (401, "human_login_failed")
    assert provider.count()["/jwks"] == 2

    provider.unavailable = set()
    clock.now += KEY_REFRESH_INTERVAL_SECONDS
    assert await login(oidc) == "subject-1"
    assert provider.count()["/jwks"] == 3


async def test_stalled_shared_fetch_ends_at_its_own_deadline(
    oidc: HumanOidc, provider: CountingProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(human_oidc, "FETCH_DEADLINE_SECONDS", 0.05)
    provider.release = asyncio.Event()

    with pytest.raises(HttpError) as failure:
        await login(oidc)
    assert (failure.value.status, failure.value.code) == (503, "human_identity_unavailable")

    provider.release.set()
    assert await login(oidc) == "subject-1"
