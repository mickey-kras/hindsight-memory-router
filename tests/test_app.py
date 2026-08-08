from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from memory_router.app import (
    AdminRateLimiter,
    Runtime,
    _admin_scope,
    _decode_segment,
    _parse_admin_item,
    _parse_memory_path,
    _send,
    create_app,
)
from memory_router.auth import AuthFailureAuditor
from memory_router.config import HindsightLimitConfig, Settings
from memory_router.errors import HttpError
from memory_router.hindsight import HindsightGatewayError
from memory_router.policy import MemoryRouterPolicy
from memory_router.quarantine.admin import QuarantineAdminService
from memory_router.quarantine.crypto import decrypt_envelope
from memory_router.quarantine.store import EncryptedDatabaseQuarantineStore, QuarantineInput
from memory_router.rate_limits import HindsightLimits, InMemorySlidingWindowRateLimiter
from memory_router.registry import DEFAULT_REGISTRY
from tests.helpers import FakeHindsight, keypair, repository


def make_settings(tmp_path, public: str, **overrides) -> Settings:
    base = Settings.from_env(
        {
            "QUARANTINE_PUBLIC_KEY": public,
            "QUARANTINE_DATABASE_URL": f"sqlite:{tmp_path / 'q.db'}",
            "MEMORY_ROUTER_TOKEN": "router",
            "MEMORY_ROUTER_ADMIN_READ_TOKEN": "read",
            "MEMORY_ROUTER_ADMIN_REVIEW_TOKEN": "review",
            "MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN": "cleanup",
            "QUARANTINE_SWEEP_INTERVAL_SECONDS": "0",
        }
    )
    return replace(base, **overrides)


async def make_runtime(tmp_path, **setting_overrides):
    public, private = keypair()
    settings = make_settings(tmp_path, public, **setting_overrides)
    repo = await repository(tmp_path)
    limiter = InMemorySlidingWindowRateLimiter()
    await limiter.initialize()
    hindsight = FakeHindsight()
    store = EncryptedDatabaseQuarantineStore(public, repo, settings.quarantine_limits, limiter)
    limits = HindsightLimits(settings.hindsight_limits, limiter)
    policy = MemoryRouterPolicy(DEFAULT_REGISTRY, hindsight, store, repo, limits)
    admin = QuarantineAdminService(repo, hindsight, DEFAULT_REGISTRY, settings.max_postpones)
    rt = Runtime(
        settings=settings,
        repository=repo,
        rate_limiter=limiter,
        hindsight=hindsight,
        policy=policy,
        admin=admin,
        audit_auth_failure=AuthFailureAuditor(store),
        admin_rate_limiter=AdminRateLimiter(settings),
    )
    return rt, store, private


async def client_for(rt: Runtime):
    app = create_app(rt)
    context = app.router.lifespan_context(app)
    await context.__aenter__()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    return app, context, client


@pytest.mark.asyncio
async def test_http_health_auth_version_retain_recall_and_denied(tmp_path):
    rt, _store, _private = await make_runtime(tmp_path)
    app, context, client = await client_for(rt)
    try:
        response = await client.get("/health")
        assert response.status_code == 200 and response.json()["status"] == "healthy"
        response = await client.get("/ready")
        assert response.status_code == 200 and response.json()["status"] == "ready"
        response = await client.get("/version")
        assert response.status_code == 401 and response.json() == {"error": "unauthorized"}
        response = await client.get("/version", headers={"authorization":"Bearer router"})
        assert response.status_code == 200 and response.json()["api_version"] == "0.9.0"

        headers = {"authorization":"Bearer router"}
        response = await client.post(
            "/v1/default/banks/main/memories",
            headers=headers,
            json={"items":[{"content":"ordinary memory"}]},
        )
        assert response.status_code == 200 and response.json() == {"accepted": True}
        assert rt.hindsight.retains[0][0] == "main"

        rt.hindsight.recalls["main"] = {"results":[{"id":"m1","text":"ordinary memory"}]}
        response = await client.post(
            "/v1/default/banks/main/memories/recall",
            headers=headers,
            json={"query":"ordinary query"},
        )
        assert response.status_code == 200 and response.json()["results"][0]["id"] == "m1"

        response = await client.get("/not-allowed", headers=headers)
        assert response.status_code == 404
        assert response.json() == {"error":"endpoint denied by memory-router policy"}
    finally:
        await client.aclose()
        await context.__aexit__(None, None, None)
        await rt.close()


@pytest.mark.asyncio
async def test_http_admin_scopes_and_review_routes(tmp_path):
    rt, store, private = await make_runtime(tmp_path)
    out = await store.put(
        QuarantineInput(
            timestamp="2026-08-07T00:00:00.000Z",
            kind="retain_request",
            reason="suspicious_content",
            writer_id="main",
            source="application",
            dedupe_key="route-admin",
            payload={"action":"retain","writer_id":"main","body":{"items":[{"content":"x"}]}},
        )
    )
    qid = out["quarantine_id"]
    app, context, client = await client_for(rt)
    try:
        assert (await client.get("/admin/quarantine/queue")).status_code == 401
        read = {"authorization":"Bearer read"}
        review = {"authorization":"Bearer review"}
        cleanup = {"authorization":"Bearer cleanup"}
        response = await client.get("/admin/quarantine/queue?limit=10&offset=0", headers=read)
        assert response.status_code == 200 and response.json()["total"] >= 1
        assert (await client.get("/admin/quarantine/stats", headers=read)).status_code == 200
        item = await client.get(f"/admin/quarantine/items/{qid}", headers=review)
        assert item.status_code == 200
        decrypted = decrypt_envelope(item.json()["encrypted"], private).to_dict()
        approved = await client.post(
            f"/admin/quarantine/items/{qid}/approve",
            headers=review,
            json={"decrypted":decrypted},
        )
        assert approved.status_code == 200 and approved.json()["approved"] is True

        response = await client.post("/admin/quarantine/cleanup", headers=cleanup, json={"dry_run":True})
        assert response.status_code == 200 and response.json()["dry_run"] is True
        assert (await client.post("/admin/quarantine/cleanup", headers=review, json={})).status_code == 401
        assert (await client.get("/admin/nope", headers=review)).status_code == 404
    finally:
        await client.aclose()
        await context.__aexit__(None, None, None)
        await rt.close()


@pytest.mark.asyncio
async def test_http_validation_bounds_rate_limits_and_gateway_error(tmp_path, capsys):
    rt, _store, _private = await make_runtime(
        tmp_path,
        max_body_bytes=40,
        hindsight_limits=HindsightLimitConfig(
            retain_writer_max=1,
            retain_global_max=1,
            recall_writer_max=1,
            recall_global_max=1,
            rate_limit_window_ms=60000,
            max_retain_items=1,
            max_retain_content_bytes=20,
            max_recall_query_bytes=20,
            max_recall_max_tokens=10,
        ),
    )
    # Policy was constructed with the original settings limits; align it for this test.
    rt.policy.limits = HindsightLimits(rt.settings.hindsight_limits, rt.rate_limiter)
    app, context, client = await client_for(rt)
    headers = {"authorization":"Bearer router", "content-type":"application/json"}
    try:
        assert (await client.post("/v1/default/banks/main/memories", headers=headers, content=b"{" )).status_code == 400
        too_big = b'{"items":[{"content":"' + b"x" * 50 + b'"}]}'
        r = await client.post("/v1/default/banks/main/memories", headers=headers, content=too_big)
        assert r.status_code == 413 and r.json()["error"] == "payload_too_large"

        # Raise a typed upstream error and ensure the public response stays bounded.
        async def fail_retain(_bank, _body):
            raise HindsightGatewayError("network", operation="retain", method="POST")
        rt.hindsight.retain = fail_retain
        r = await client.post(
            "/v1/default/banks/main/memories",
            headers=headers,
            json={"items":[{"content":"x"}]},
        )
        assert r.status_code == 502 and r.json()["error"] == "hindsight_unavailable"
        assert "upstream request failed" in capsys.readouterr().err
    finally:
        await client.aclose()
        await context.__aexit__(None, None, None)
        await rt.close()


@pytest.mark.asyncio
async def test_app_helpers_and_admin_rate_limiter(tmp_path):
    public, _ = keypair()
    settings = make_settings(tmp_path, public, admin_rate_read_max=1, admin_rate_write_max=1)
    limiter = AdminRateLimiter(settings)
    await limiter.consume("read")
    with pytest.raises(HttpError) as exc:
        await limiter.consume("read")
    assert exc.value.code == "admin_rate_limited"

    assert _parse_memory_path("/v1/default/banks/main/memories") == ("main", "retain")
    assert _parse_memory_path("/v1/default/banks/a%20b/memories/recall") == ("a b", "recall")
    assert _parse_memory_path("/x") is None
    assert _parse_admin_item("/admin/quarantine/items/q_x_0123456789abcdef") == ("q_x_0123456789abcdef", "read")
    assert _parse_admin_item("/x") is None
    assert _admin_scope("GET", "/x") == "read"
    assert _admin_scope("POST", "/admin/quarantine/cleanup") == "cleanup"
    assert _admin_scope("POST", "/x") == "review"
    with pytest.raises(HttpError):
        _decode_segment("%zz")
    with pytest.raises(HttpError):
        _decode_segment("%ff")
    assert _decode_segment("a%20b") == "a b"
    response = _send(201, {"x":1}, {"x-test":"yes"})
    assert response.status_code == 201 and response.headers["x-test"] == "yes"


@pytest.mark.asyncio
async def test_http_query_validation_and_body_shapes(tmp_path):
    rt, _store, _private = await make_runtime(tmp_path)
    app, context, client = await client_for(rt)
    read = {"authorization":"Bearer read"}
    cleanup = {"authorization":"Bearer cleanup"}
    review = {"authorization":"Bearer review"}
    try:
        for query in ["?limit=0", "?limit=x", "?limit=1&limit=2", "?offset=-1"]:
            r = await client.get("/admin/quarantine/queue" + query, headers=read)
            assert r.status_code == 400 and r.json()["error"] == "invalid_query"
        r = await client.post("/admin/quarantine/cleanup", headers=cleanup, json=[])
        assert r.status_code == 400 and r.json()["error"] == "invalid_request"
        r = await client.post("/admin/quarantine/items/q_x_0123456789abcdef/approve", headers=review, json=[])
        assert r.status_code == 400
    finally:
        await client.aclose()
        await context.__aexit__(None, None, None)
        await rt.close()


@pytest.mark.asyncio
async def test_build_runtime_lifecycle_ready_failure_and_sweeper(tmp_path, monkeypatch, capsys):
    import memory_router.app as app_module

    public, _ = keypair()
    settings = make_settings(tmp_path, public, sweep_interval_seconds=0)
    built = await app_module.build_runtime(settings)
    assert built.repository.db.dialect == "sqlite"
    await built.close()

    rt, _store, _private = await make_runtime(tmp_path / "ready")
    async def bad_ping():
        raise RuntimeError("db down")
    monkeypatch.setattr(rt.repository, "ping", bad_ping)
    app, context, client = await client_for(rt)
    try:
        response = await client.get("/ready")
        assert response.status_code == 503 and response.json()["status"] == "not_ready"
    finally:
        await client.aclose(); await context.__aexit__(None, None, None); await rt.close()

    calls = {"sleep":0,"sweep":0,"prune":0}
    async def fake_sleep(_seconds):
        calls["sleep"] += 1
        if calls["sleep"] > 1:
            raise __import__("asyncio").CancelledError()
    class Repo:
        async def sweep_expired_items(self, _at):
            calls["sweep"] += 1
            return 1000 if calls["sweep"] == 1 else 0
        async def prune_events_before(self, _cutoff, _at):
            calls["prune"] += 1
            return 1000 if calls["prune"] == 1 else 0
    monkeypatch.setattr(app_module.asyncio, "sleep", fake_sleep)
    fake = SimpleNamespace(
        settings=SimpleNamespace(sweep_interval_seconds=1,event_retention_days=1),
        repository=Repo(),
    )
    with pytest.raises(__import__("asyncio").CancelledError):
        await app_module._sweeper(fake)
    assert calls["sweep"] == 2 and calls["prune"] == 2

    calls["sleep"] = 0
    class BadRepo:
        async def sweep_expired_items(self, _at): raise RuntimeError("boom")
        async def prune_events_before(self, *_): return 0
    fake.repository = BadRepo()
    with pytest.raises(__import__("asyncio").CancelledError):
        await app_module._sweeper(fake)
    assert "retention sweep failed" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_create_app_owned_runtime_lifespan(monkeypatch):
    import memory_router.app as app_module

    class Built:
        closed = False
        async def close(self): self.closed = True
    built = Built()
    async def fake_build(): return built
    monkeypatch.setattr(app_module, "build_runtime", fake_build)
    app = app_module.create_app()
    async with app.router.lifespan_context(app):
        pass
    assert built.closed is True
