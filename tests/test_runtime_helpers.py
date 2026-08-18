from __future__ import annotations

from ipaddress import IPv4Address
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

from memory_router import __main__ as main_module
from memory_router import app as app_module
from memory_router.errors import HttpError
from memory_router.hindsight import HindsightGateway, HindsightGatewayError
from memory_router.maintenance import (
    cleanup,
    cleanup_params,
    preview_cleanup,
    prune_events_before,
    sweep_expired,
)


@pytest.mark.asyncio
async def test_hindsight_gateway_success_and_error_paths(httpx_mock: HTTPXMock) -> None:
    with pytest.raises(RuntimeError):
        HindsightGateway("http://x", None, 0)
    gateway = HindsightGateway("http://x/", "key", 100)

    healthy = {"status": "healthy", "database": "connected"}
    httpx_mock.add_response(url="http://x/health", json=healthy)
    assert await gateway.health() == healthy
    request = httpx_mock.get_request(url="http://x/health")
    assert request is not None
    assert request.headers["authorization"] == "Bearer key"

    version = {
        "api_version": "0.9.0",
        "features": {
            "observations": True,
            "mcp": True,
            "worker": True,
            "bank_config_api": True,
            "bank_llm_health": True,
            "file_upload_api": True,
            "document_export_api": True,
            "document_import_api": True,
            "audit_log": True,
            "llm_trace": True,
            "store_document_text": True,
        },
    }
    httpx_mock.add_response(url="http://x/version", json=version)
    assert await gateway.version() == {
        "api_version": "0.9.0",
        "features": {
            "observations": True,
            "mcp": False,
            "worker": True,
            "bank_config_api": True,
            "bank_llm_health": False,
            "file_upload_api": False,
            "document_export_api": False,
            "document_import_api": False,
            "audit_log": True,
            "llm_trace": True,
            "store_document_text": True,
        },
    }

    httpx_mock.add_response(url="http://x/v1/default/banks/a%2Fb/memories", json={"ok": True})
    await gateway.retain("a/b", {"items": []})
    request = httpx_mock.get_request(url="http://x/v1/default/banks/a%2Fb/memories")
    assert request is not None
    assert request.url.path.endswith("/a/b/memories")
    assert "%2F" in str(request.url)

    recall_url = "http://x/v1/default/banks/main/memories/recall"
    httpx_mock.add_response(url=recall_url, json={"results": [{"id": "1", "text": "x"}]})
    assert (await gateway.recall("main", {"query": "x"}))["results"][0]["text"] == "x"

    httpx_mock.add_response(url=recall_url, json={"bad": True})
    with pytest.raises(HindsightGatewayError) as invalid_schema:
        await gateway.recall("main", {"query": "x"})
    assert invalid_schema.value.code == "hindsight_invalid_response"

    httpx_mock.add_response(url="http://x/health", status_code=500, json={})
    with pytest.raises(HindsightGatewayError) as http_error:
        await gateway.health()
    assert http_error.value.upstream_status == 500

    httpx_mock.add_exception(httpx.ReadTimeout("late"), url="http://x/health")
    with pytest.raises(HindsightGatewayError) as timeout:
        await gateway.health()
    assert timeout.value.status == 504

    httpx_mock.add_exception(httpx.ConnectError("down"), url="http://x/health")
    with pytest.raises(HindsightGatewayError) as network:
        await gateway.health()
    assert network.value.code == "hindsight_unavailable"

    httpx_mock.add_response(url="http://x/health", content=b"")
    with pytest.raises(HindsightGatewayError) as empty_health:
        await gateway.health()
    assert empty_health.value.code == "hindsight_invalid_response"

    httpx_mock.add_response(
        url="http://x/health", content=b"not-json", headers={"content-type": "application/json"}
    )
    with pytest.raises(HindsightGatewayError) as malformed:
        await gateway.health()
    assert malformed.value.code == "hindsight_invalid_response"

    invalidate_url = "http://x/v1/default/banks/a%2Fb/memories/m%2F1"
    httpx_mock.add_response(url=invalidate_url, json={"ok": True})
    await gateway.invalidate_memory("a/b", "m/1", "reason")
    request = httpx_mock.get_request(url=invalidate_url)
    assert request is not None
    assert "%2F" in str(request.url)

    await gateway.close()


def test_hindsight_error_details_variants() -> None:
    for kind, status in (
        ("timeout", 504),
        ("http", 502),
        ("invalid-response", 502),
        ("network", 502),
    ):
        err = HindsightGatewayError(
            kind, upstream_status=503, operation="x", method="GET", timeout_ms=1
        )  # type: ignore[arg-type]
        assert err.status == status and err.details()["upstream_status"] == 503


class Tx:
    def __init__(
        self,
        *,
        dialect: str = "sqlite",
        one: dict[str, object] | None = None,
        many: list[dict[str, object]] | None = None,
    ) -> None:
        self.dialect = dialect
        self.one = one
        self.many = list(many or [])
        self.calls: list[tuple[str, object]] = []

    async def fetchone(self, sql: str, params: object = None) -> dict[str, object] | None:
        self.calls.append((sql, params))
        return self.one

    async def fetchall(self, sql: str, params: object = None) -> list[dict[str, object]]:
        self.calls.append((sql, params))
        return self.many

    async def execute(self, sql: str, params: object = None) -> None:
        self.calls.append((sql, params))


class Ctx:
    def __init__(self, tx: Tx) -> None:
        self.tx = tx

    async def __aenter__(self) -> Tx:
        return self.tx

    async def __aexit__(self, *args: object) -> None:
        return None


class Repo:
    def __init__(self, tx: Tx) -> None:
        self.db = SimpleNamespace(transaction=lambda: Ctx(tx))


def test_cleanup_params_validation() -> None:
    where, params = cleanup_params("pending", ["a"], "2020")
    assert where == "status IN ('pending','postponed') AND reason IN (?) AND created_at < ?"
    assert params == ["a", "2020"]

    where, params = cleanup_params("all", None, None)
    assert where == (
        "status NOT IN ('review_in_progress','review_side_effect_started',"
        "'review_side_effect_completed','reviewed_allowed','reviewed_blocked')"
    )
    assert params == []

    with pytest.raises(HttpError) as invalid_scope:
        cleanup_params("bad", None, None)
    assert invalid_scope.value.status == 400

    with pytest.raises(HttpError) as invalid_reasons:
        cleanup_params("all", "a", None)  # type: ignore[arg-type]
    assert invalid_reasons.value.status == 400

    with pytest.raises(HttpError) as invalid_reason_item:
        cleanup_params("all", ["a", 1], None)  # type: ignore[list-item]
    assert invalid_reason_item.value.status == 400

    reasons = [str(i) for i in range(7)]
    where, params = cleanup_params("all", reasons, None)
    assert where == (
        "status NOT IN ('review_in_progress','review_side_effect_started',"
        "'review_side_effect_completed','reviewed_allowed','reviewed_blocked') "
        "AND reason IN (?,?,?,?,?,?,?)"
    )
    assert params == reasons


@pytest.mark.asyncio
async def test_maintenance_preview_cleanup_sweep_and_prune() -> None:
    tx = Tx(one={"count": 2, "encrypted_bytes": 9})
    assert await preview_cleanup(Repo(tx), "pending", None, None) == {
        "count": 2,
        "encrypted_bytes": 9,
    }

    rows = [
        {"quarantine_id": "a", "encrypted_bytes": 4},
        {"quarantine_id": "b", "encrypted_bytes": 5},
    ]
    tx = Tx(many=rows)
    assert await cleanup(Repo(tx), "all", ["x"], None, 2, "now") == {
        "count": 2,
        "encrypted_bytes": 9,
    }
    assert any("DELETE FROM quarantine_items" in sql for sql, _ in tx.calls)
    with pytest.raises(Exception) as changed:
        await cleanup(Repo(Tx(many=rows)), "all", None, None, 1, "now")
    assert getattr(changed.value, "code", None) == "quarantine_cleanup_changed"

    expired = [{"quarantine_id": "a", "expires_at": "old"}]
    assert await sweep_expired(Repo(Tx(dialect="postgres", many=expired)), "now") == 1
    assert await sweep_expired(Repo(Tx(many=[])), "now") == 0
    events = [{"event_id": "1"}, {"event_id": "2"}]
    assert await prune_events_before(Repo(Tx(many=events)), "old", "now") == 2
    assert await prune_events_before(Repo(Tx(many=[])), "old", "now") == 0


def test_app_scope_and_now() -> None:
    assert app_module._scope("GET", "/x") == "read"
    assert app_module._scope("POST", "/admin/quarantine/cleanup") == "cleanup"
    assert app_module._scope("POST", "/x") == "review"
    assert app_module._now().endswith("Z")


def test_main_runs_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEMORY_ROUTER_PORT", "8891")
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_run(*args: object, **kwargs: object) -> None:
        calls.append((args, kwargs))

    monkeypatch.setattr(main_module.uvicorn, "run", fake_run)
    main_module.main()
    assert calls == [
        (
            (main_module.app,),
            {
                "host": str(IPv4Address(0)),
                "port": 8891,
                "access_log": False,
                "log_config": None,
            },
        )
    ]


@pytest.mark.asyncio
async def test_runtime_start_uses_dedicated_postgres_rate_limit_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QUARANTINE_DATABASE_URL", "postgresql://db")
    monkeypatch.setenv("QUARANTINE_SWEEP_INTERVAL_SECONDS", "0")
    monkeypatch.setattr(app_module, "assert_no_private_key_environment", lambda: None)
    monkeypatch.setattr(app_module, "assert_auth_environment", lambda: None)

    primary_db = SimpleNamespace()
    create_database = AsyncMock(return_value=primary_db)
    validate_storage = AsyncMock()
    recover_interrupted = AsyncMock()
    repository = SimpleNamespace(close=AsyncMock())
    monkeypatch.setattr(app_module, "create_database", create_database)
    monkeypatch.setattr(app_module, "validate_storage", validate_storage)
    monkeypatch.setattr(app_module, "recover_interrupted", recover_interrupted)
    monkeypatch.setattr(app_module, "QuarantineRepository", lambda database: repository)

    rate_db = SimpleNamespace(initialize=AsyncMock(), close=AsyncMock())
    postgres_database_calls: list[tuple[str, int]] = []

    def postgres_database(database_url: str, *, max_size: int = 5) -> object:
        postgres_database_calls.append((database_url, max_size))
        return rate_db

    rate_limiter = SimpleNamespace(initialize=AsyncMock())
    monkeypatch.setattr(app_module, "PostgresDatabase", postgres_database)
    monkeypatch.setattr(app_module, "PostgresRateLimiter", lambda database: rate_limiter)

    store = object()
    hindsight = SimpleNamespace(close=AsyncMock())
    registry = object()
    hindsight_limits = object()
    policy = object()
    admin = object()
    auditor = object()
    hindsight_limiter_calls: list[object] = []

    monkeypatch.setattr(app_module, "QuarantineStore", lambda *args: store)
    monkeypatch.setattr(app_module, "HindsightGateway", lambda *args: hindsight)
    monkeypatch.setattr(app_module, "load_registry", lambda path: registry)

    def make_hindsight_limits(config: object, limiter: object) -> object:
        hindsight_limiter_calls.append(limiter)
        return hindsight_limits

    monkeypatch.setattr(app_module, "HindsightLimits", make_hindsight_limits)
    monkeypatch.setattr(app_module, "RouterPolicy", lambda *args: policy)
    monkeypatch.setattr(app_module, "QuarantineAdminService", lambda *args: admin)
    monkeypatch.setattr(app_module, "AuthFailureAuditor", lambda value: auditor)

    runtime = app_module.Runtime()
    await runtime.start()

    create_database.assert_awaited_once_with("postgresql://db")
    validate_storage.assert_awaited_once_with(primary_db, "postgresql://db")
    recover_interrupted.assert_awaited_once()
    assert postgres_database_calls == [("postgresql://db", 2)]
    rate_db.initialize.assert_awaited_once()
    rate_limiter.initialize.assert_awaited_once()
    assert runtime.database is primary_db
    assert runtime.rate_limit_database is rate_db
    assert runtime.quarantine_limiter is rate_limiter
    assert hindsight_limiter_calls == [rate_limiter]
    assert runtime.hindsight is hindsight
    assert runtime.policy is policy
    assert runtime.admin is admin
    assert runtime.auditor is auditor
    assert runtime.sweeper is None

    await runtime.stop()
    hindsight.close.assert_awaited_once()
    rate_db.close.assert_awaited_once()
    repository.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_runtime_stop_and_sweep(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    rt = app_module.Runtime()
    rt.hindsight = SimpleNamespace(close=AsyncMock())
    rt.repository = SimpleNamespace(close=AsyncMock())
    await rt.stop()
    rt.hindsight.close.assert_awaited_once()
    rt.repository.close.assert_awaited_once()

    repo = SimpleNamespace()
    rt.repository = repo
    sleep_calls = 0

    async def fake_sleep(_: int) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            raise RuntimeError("stop")

    monkeypatch.setattr(app_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(app_module, "sweep_expired", AsyncMock(side_effect=RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="stop"):
        await rt._sweep_loop(1, 0)
    assert "quarantine_sweeper_failed" in caplog.text
