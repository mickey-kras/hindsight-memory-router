from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from memory_router import app as app_module
from memory_router import probes
from memory_router.config import RouterSettings, assert_auth_environment
from memory_router.db import create_database
from memory_router.errors import HttpError
from memory_router.human_auth import ExchangeLogin, HumanAuth, StartLogin
from memory_router.human_auth_config import HumanAuthConfig, generation_for, load_human_config
from memory_router.human_auth_store import HumanAuthStore
from memory_router.human_oidc import HumanOidc
from memory_router.principals import PrincipalGrant, PrincipalRegistry, PrincipalResolver
from memory_router.rate_limit import InMemoryConcurrencyLimiter, InMemoryRateLimiter
from tests.request_helpers import request

VERIFIER = "x" * 43
STATE = "y" * 43
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
)
REDIRECT = "http://127.0.0.1:49152/callback"


class Provider:
    def __init__(self) -> None:
        self.key = RSAKey.generate_key(2048)
        self.key.ensure_kid()
        self.nonce = ""
        self.claims: dict[str, object] = {}
        self.metadata_changes: dict[str, object] = {}
        self.calls: list[httpx.Request] = []
        self.status = 200
        self.tamper_signature = False
        self.algorithm = "RS256"

    def respond(self, incoming: httpx.Request) -> httpx.Response:
        self.calls.append(incoming)
        if incoming.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://id.example",
                    "authorization_endpoint": "https://id.example/authorize",
                    "token_endpoint": "https://id.example/token",
                    "jwks_uri": "https://id.example/jwks",
                    "code_challenge_methods_supported": ["S256"],
                    "response_types_supported": ["code"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    **self.metadata_changes,
                },
            )
        if incoming.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [self.key.as_dict(private=False)]})
        assert incoming.url.path == "/token"
        assert parse_qs(incoming.content.decode())["code_verifier"] == [VERIFIER]
        now = int(time.time())
        token = jwt.encode(
            {"alg": self.algorithm, "kid": self.key.kid},
            {
                "iss": "https://id.example",
                "aud": "coding-agent",
                "sub": "subject-1",
                "iat": now,
                "exp": now + 300,
                "nonce": self.nonce,
                **self.claims,
            },
            self.key,
        )
        if self.tamper_signature:
            header, body, signature = token.split(".")
            signature = ("A" if signature[0] != "A" else "B") + signature[1:]
            token = ".".join((header, body, signature))
        return httpx.Response(
            self.status, json={"id_token": token}, headers={"location": "https://evil.example"}
        )


@pytest.fixture
def provider() -> Provider:
    return Provider()


@pytest.fixture
async def service(provider: Provider) -> AsyncIterator[HumanAuth]:
    db = await create_database("sqlite::memory:")
    registry = PrincipalRegistry.model_validate(
        {
            "principals": {
                "human-test": {
                    "source": "human",
                    "grants": [{"bank": "personal", "scopes": ["bank.list", "memory.recall"]}],
                }
            }
        }
    )
    config = HumanAuthConfig(
        router_url="https://router.example",
        issuer="https://id.example",
        client_id="coding-agent",
        subjects={"subject-1": "human-test"},
    )
    resolver = PrincipalResolver(registry)
    store = HumanAuthStore(db, generation_for(config, registry))
    await store.initialize()
    oidc = HumanOidc(config, httpx.AsyncClient(transport=httpx.MockTransport(provider.respond)))
    result = HumanAuth(
        config, store, resolver, InMemoryRateLimiter(), InMemoryConcurrencyLimiter(), oidc
    )
    resolver.human_authenticate = result.authenticate
    yield result
    await result.close()
    await db.close()


async def start(service: HumanAuth, provider: Provider) -> ExchangeLogin:
    started = await service.start(
        StartLogin(redirect_uri=REDIRECT, state=STATE, code_challenge=CHALLENGE)
    )
    query = parse_qs(urlsplit(started["authorization_url"]).query)
    assert query["scope"] == ["openid"] and query["code_challenge_method"] == ["S256"]
    provider.nonce = query["nonce"][0]
    return ExchangeLogin(
        transaction_id=started["transaction_id"],
        code="authorization-code",
        state=STATE,
        code_verifier=VERIFIER,
    )


async def test_exchange_authentication_grants_signout_and_legacy_separation(
    service: HumanAuth, provider: Provider
) -> None:
    login = await start(service, provider)
    issued = await service.exchange(login)
    authorization = "Bearer " + str(issued["token"])
    assert issued["token_type"] == "Bearer"  # noqa: S105 - OAuth token type
    assert (
        isinstance(issued["expires_at"], int)
        and int(time.time()) < issued["expires_at"] <= int(time.time()) + 3600
    )
    authenticated = await service.resolver.authenticate_request(authorization)
    assert authenticated.session is not None
    assert authenticated.session.principal_id == "human-test"
    assert service.resolver.authorize(authenticated.session, "memory.recall", "personal")
    assert not service.resolver.authorize(authenticated.session, "memory.retain", "personal")
    assert service.resolver.authenticate(authorization).session is None
    with pytest.raises(HttpError, match="interactive login"):
        await service.exchange(login)
    signed_out = await service.dispatch(
        request("POST", "/auth/human/sign-out", headers={"authorization": authorization}),
        "sign-out",
    )
    assert signed_out.status_code == 200 and signed_out.headers["cache-control"] == "no-store"
    assert (await service.authenticate(authorization)).session is None


@pytest.mark.parametrize(
    "changed",
    [
        {"iss": "https://evil.example"},
        {"aud": "wrong-client"},
        {"aud": ["coding-agent", "other"]},
        {"exp": 1},
        {"nonce": "wrong"},
        {"iat": 9999999999},
        {"nbf": 9999999999},
        {"azp": "wrong-client"},
        {"sub": "unmapped"},
        {"exp": "9999999999"},
    ],
)
async def test_invalid_identity_never_issues_session(
    service: HumanAuth, provider: Provider, changed: dict[str, object]
) -> None:
    login = await start(service, provider)
    provider.claims = changed
    with pytest.raises(HttpError) as failure:
        await service.exchange(login)
    assert failure.value.status == 401
    async with service.store.db.transaction() as tx:
        assert await tx.fetchone("SELECT COUNT(*) AS n FROM human_auth_sessions") == {"n": 0}


@pytest.mark.parametrize(
    "changed",
    [
        {"issuer": "https://evil.example"},
        {"token_endpoint": "http://id.example/token"},
        {"code_challenge_methods_supported": ["plain"]},
        {"jwks_uri": "https://user:password@id.example/jwks"},
    ],
)
async def test_discovery_trust(
    service: HumanAuth, provider: Provider, changed: dict[str, object]
) -> None:
    provider.metadata_changes = changed
    with pytest.raises(HttpError):
        await start(service, provider)
    assert len(provider.calls) == 1


async def test_failed_exchange_is_consumed_and_redirect_not_followed(
    service: HumanAuth, provider: Provider
) -> None:
    login = await start(service, provider)
    provider.status = 302
    with pytest.raises(HttpError):
        await service.exchange(login)
    provider.status = 200
    with pytest.raises(HttpError):
        await service.exchange(login)
    assert all(incoming.url.host == "id.example" for incoming in provider.calls)


@pytest.mark.parametrize(
    "body",
    [
        {
            "redirect_uri": REDIRECT,
            "state": STATE,
            "code_challenge": CHALLENGE,
            "grants": ["bank.admin"],
        },
        {
            "redirect_uri": "http://evil.example/callback",
            "state": STATE,
            "code_challenge": CHALLENGE,
        },
        b'{"state":"a","state":"b"}',
        b"{" + b"x" * 8192,
    ],
)
async def test_strict_request_boundary(
    service: HumanAuth, provider: Provider, body: object
) -> None:
    response = await service.dispatch(request("POST", "/auth/human/start", body=body), "start")
    assert response.status_code in {400, 413}
    assert response.headers["cache-control"] == "no-store"
    assert not provider.calls


async def test_invalid_attempts_consume_global_rate_budget(service: HumanAuth) -> None:
    for _ in range(20):
        result = await service.dispatch(request("POST", "/auth/human/start", body={}), "start")
        assert result.status_code == 400
    result = await service.dispatch(request("POST", "/auth/human/start", body={}), "start")
    assert result.status_code == 429


@pytest.mark.parametrize("algorithm,tamper", [("RS384", False), ("RS256", True)])
async def test_signature_algorithm_and_integrity(
    service: HumanAuth,
    provider: Provider,
    algorithm: str,
    tamper: bool,
) -> None:
    login = await start(service, provider)
    provider.algorithm = algorithm
    provider.tamper_signature = tamper
    with pytest.raises(HttpError) as failure:
        await service.exchange(login)
    assert failure.value.status == 401


async def test_provider_concurrency_is_bounded(
    service: HumanAuth,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered, release = asyncio.Event(), asyncio.Event()
    running = 0

    async def blocked(**parameters: str) -> str:
        nonlocal running
        running += 1
        if running == 8:
            entered.set()
        await release.wait()
        return "https://id.example/authorize"

    monkeypatch.setattr(service.oidc, "authorization_url", blocked)
    pending = [
        asyncio.create_task(
            service.start(
                StartLogin(
                    redirect_uri=REDIRECT,
                    state=STATE,
                    code_challenge=CHALLENGE,
                )
            )
        )
        for _ in range(8)
    ]
    try:
        await asyncio.wait_for(entered.wait(), timeout=2)
        response = await service.dispatch(
            request(
                "POST",
                "/auth/human/start",
                body={
                    "redirect_uri": REDIRECT,
                    "state": STATE,
                    "code_challenge": CHALLENGE,
                },
            ),
            "start",
        )
        assert response.status_code == 429 and running == 8
        async with service.store.db.transaction() as tx:
            assert await tx.fetchone("SELECT COUNT(*) AS n FROM human_auth_logins") == {"n": 8}
    finally:
        release.set()
        await asyncio.gather(*pending)


@pytest.mark.parametrize("cycle_policy", [False, True])
async def test_policy_activation_during_verified_exchange_requires_fresh_login(
    service: HumanAuth,
    provider: Provider,
    cycle_policy: bool,
) -> None:
    login = await start(service, provider)
    entered, release = asyncio.Event(), asyncio.Event()

    async def paused_provider(incoming: httpx.Request) -> httpx.Response:
        if incoming.url.path == "/token":
            entered.set()
            await release.wait()
        return provider.respond(incoming)

    await service.oidc.client.aclose()
    service.oidc.client = httpx.AsyncClient(transport=httpx.MockTransport(paused_provider))
    pending = asyncio.create_task(service.exchange(login))
    try:
        await asyncio.wait_for(entered.wait(), timeout=2)
        if cycle_policy:
            other = HumanAuthStore(service.store.db, hashlib.sha256(b"other-policy").hexdigest())
            await other.initialize(check_generation=False)
            await other.activate()
        await service.store.activate()
        release.set()
        with pytest.raises(HttpError) as failure:
            await pending
        assert failure.value.status == 401
        assert failure.value.code == "human_login_required"
        async with service.store.db.transaction() as tx:
            assert await tx.fetchone("SELECT COUNT(*) AS n FROM human_auth_sessions") == {"n": 0}
        issued = await service.exchange(await start(service, provider))
        assert (await service.authenticate("Bearer " + str(issued["token"]))).session is not None
    finally:
        release.set()
        if not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.parametrize("endpoint", ["/.well-known/openid-configuration", "/token", "/jwks"])
@pytest.mark.parametrize("status", [429, 500, 503])
async def test_provider_failures_are_unavailability(
    service: HumanAuth,
    provider: Provider,
    endpoint: str,
    status: int,
) -> None:
    login = await start(service, provider)

    def failed_provider(incoming: httpx.Request) -> httpx.Response:
        if incoming.url.path == endpoint:
            return httpx.Response(status, json={"error": "private-provider-detail"})
        return provider.respond(incoming)

    await service.oidc.client.aclose()
    service.oidc.client = httpx.AsyncClient(transport=httpx.MockTransport(failed_provider))
    response = await service.dispatch(
        request("POST", "/auth/human/exchange", body=login.model_dump()), "exchange"
    )
    assert response.status_code == 503
    assert json.loads(response.body)["error"] == "human_identity_unavailable"
    assert b"private-provider-detail" not in response.body


async def test_failed_start_removes_unreturned_transaction(
    service: HumanAuth, provider: Provider
) -> None:
    provider.metadata_changes = {"issuer": "https://untrusted.example"}
    response = await service.dispatch(
        request(
            "POST",
            "/auth/human/start",
            body={
                "redirect_uri": REDIRECT,
                "state": STATE,
                "code_challenge": CHALLENGE,
            },
        ),
        "start",
    )
    assert response.status_code == 401
    async with service.store.db.transaction() as tx:
        assert await tx.fetchone("SELECT COUNT(*) AS n FROM human_auth_logins") == {"n": 0}


async def test_invalid_authorization_code_remains_authentication_failure(
    service: HumanAuth, provider: Provider
) -> None:
    login = await start(service, provider)
    provider.status = 400
    response = await service.dispatch(
        request("POST", "/auth/human/exchange", body=login.model_dump()), "exchange"
    )
    assert response.status_code == 401


async def test_pair_intersection_and_current_bank_policy(
    service: HumanAuth, provider: Provider
) -> None:
    issued = await service.exchange(await start(service, provider))
    principal = service.resolver.registry.principals["human-test"]
    principal.grants = [
        PrincipalGrant(bank="personal", scopes=["memory.retain"]),
        PrincipalGrant(bank="other", scopes=["memory.recall"]),
    ]
    authenticated = await service.authenticate("Bearer " + str(issued["token"]))
    assert authenticated.session is not None and authenticated.session.grants == ()


async def test_storage_failure_denies_and_redacts(
    service: HumanAuth, caplog: pytest.LogCaptureFixture
) -> None:
    await service.store.db.close()
    response = await service.dispatch(
        request(
            "POST",
            "/auth/human/start",
            body={
                "redirect_uri": REDIRECT,
                "state": STATE,
                "code_challenge": CHALLENGE,
            },
        ),
        "start",
    )
    assert response.status_code == 503
    assert STATE not in caplog.text and CHALLENGE not in caplog.text


async def test_http_dispatch_disabled_enabled_and_human_admin_denial(
    service: HumanAuth, provider: Provider, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module.runtime, "human_auth", None)
    response = await app_module.dispatch("auth/human/start", request("POST", "/auth/human/start"))
    assert response.status_code == 404
    monkeypatch.setattr(app_module.runtime, "human_auth", service)
    response = await app_module.dispatch(
        "auth/human/start",
        request(
            "POST",
            "/auth/human/start",
            body={
                "redirect_uri": REDIRECT,
                "state": STATE,
                "code_challenge": CHALLENGE,
            },
        ),
    )
    assert response.status_code == 200
    issued = await service.exchange(await start(service, provider))
    from memory_router.principal_gate import principal_token_present

    assert not principal_token_present("Bearer " + str(issued["token"]))


@pytest.mark.parametrize("path", ["/health", "/health/ready", "/ready"])
@pytest.mark.parametrize("invalidation", ["expired", "revoked"])
async def test_human_readiness_authentication_and_privileged_route_exclusion(
    service: HumanAuth,
    provider: Provider,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    invalidation: str,
) -> None:
    issued = await service.exchange(await start(service, provider))
    headers = {"authorization": "Bearer " + str(issued["token"])}
    upstream = {"status": "healthy", "database": "connected", "db_acquire_ms": 0.4}
    monkeypatch.setattr(app_module.runtime, "router_token", None)
    monkeypatch.setattr(app_module.runtime, "allow_anonymous", False)
    monkeypatch.setattr(app_module.runtime, "principal_resolver", service.resolver)
    monkeypatch.setattr(app_module.runtime, "repository", SimpleNamespace(ping=AsyncMock()))
    monkeypatch.setattr(
        app_module.runtime, "hindsight", SimpleNamespace(health=AsyncMock(return_value=upstream))
    )
    monkeypatch.setattr(
        app_module.runtime, "auditor", SimpleNamespace(log_failure=Mock(), persist=AsyncMock())
    )
    monkeypatch.setattr(app_module.runtime, "auth_prefilter", InMemoryRateLimiter())
    monkeypatch.setattr(app_module.runtime, "auth_limiter", InMemoryRateLimiter())
    monkeypatch.setattr(app_module.runtime, "admin_tokens", {})
    monkeypatch.setattr(app_module.runtime, "metrics_enabled", True)
    monkeypatch.setattr(probes.readiness, "cache", None)

    response = await app_module.health_ready(request("GET", path, headers=headers))
    assert response.status_code == 200 and json.loads(response.body) == upstream
    for privileged_path in ("/admin/quarantine/stats", "/metrics"):
        response = await app_module.dispatch(
            privileged_path.lstrip("/"), request("GET", privileged_path, headers=headers)
        )
        assert response.status_code == 401

    if invalidation == "revoked":
        await service.store.revoke(str(issued["token"]).split("_")[1])
    else:
        async with service.store.db.transaction() as tx:
            await tx.execute("UPDATE human_auth_sessions SET expires_at_ms=0")
    response = await app_module.health_ready(request("GET", path, headers=headers))
    assert response.status_code == 200 and json.loads(response.body) == {"status": "healthy"}


def test_config_and_conditional_principal_keys(tmp_path: Path, service: HumanAuth) -> None:
    path = tmp_path / "human.json"
    path.write_text(service.config.model_dump_json())
    assert load_human_config(str(path), service.resolver.registry) == service.config
    path.write_text(
        json.dumps({**service.config.model_dump(), "subjects": {"unknown": "control-plane"}})
    )
    with pytest.raises(RuntimeError, match="invalid human authentication"):
        load_human_config(str(path), service.resolver.registry)
    with pytest.raises(ValueError):
        PrincipalRegistry.model_validate({"principals": {"app": {"keys": []}}})
    with pytest.raises(ValueError):
        PrincipalRegistry.model_validate(
            {
                "principals": {
                    "human": {
                        "source": "human",
                        "grants": [{"bank": "a", "scopes": ["bank.admin"]}],
                    }
                }
            }
        )
    with pytest.raises(RuntimeError, match="requires MEMORY_ROUTER_PRINCIPALS"):
        assert_auth_environment(RouterSettings(MEMORY_ROUTER_HUMAN_AUTH=str(path)))
