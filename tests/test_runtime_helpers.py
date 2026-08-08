from __future__ import annotations

from ipaddress import IPv4Address
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from memory_router import __main__ as main_module
from memory_router import app as app_module
from memory_router.errors import HttpError
from memory_router.hindsight import HindsightGateway, HindsightGatewayError
from memory_router.key_bootstrap import bootstrap_keys
from memory_router.maintenance import (
    cleanup,
    cleanup_params,
    preview_cleanup,
    prune_events_before,
    sweep_expired,
)


class FakeResponse:
    def __init__(
        self,
        status: int = 200,
        value: object = None,
        *,
        content: bytes | None = None,
        error: Exception | None = None,
    ) -> None:
        self.status_code = status
        self.is_success = 200 <= status < 300
        self._value = value
        self.content = content if content is not None else (b"x" if value is not None else b"")
        self.error = error
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True

    def json(self) -> object:
        if self.error:
            raise self.error
        return self._value


@pytest.mark.asyncio
async def test_hindsight_gateway_success_and_error_paths() -> None:
    with pytest.raises(RuntimeError):
        HindsightGateway("http://x", None, 0)
    gateway = HindsightGateway("http://x/", "key", 100)
    request = AsyncMock(return_value=FakeResponse(value={"ok": True}))
    gateway.client.request = request
    assert await gateway.health() == {"ok": True}
    assert await gateway.version() == {"ok": True}
    await gateway.retain("a/b", {"items": []})
    request.assert_awaited()
    assert request.await_args.kwargs["headers"]["authorization"] == "Bearer key"
    assert "%2F" in request.await_args.args[1]

    request.return_value = FakeResponse(value={"results": [{"id": "1", "text": "x"}]})
    assert (await gateway.recall("main", {"query": "x"}))["results"][0]["text"] == "x"
    request.return_value = FakeResponse(value={"bad": True})
    with pytest.raises(HindsightGatewayError) as invalid_schema:
        await gateway.recall("main", {"query": "x"})
    assert invalid_schema.value.code == "hindsight_invalid_response"

    request.return_value = FakeResponse(status=500, value={})
    with pytest.raises(HindsightGatewayError) as http_error:
        await gateway.health()
    assert http_error.value.upstream_status == 500 and request.return_value.closed

    request.side_effect = httpx.ReadTimeout("late")
    with pytest.raises(HindsightGatewayError) as timeout:
        await gateway.health()
    assert timeout.value.status == 504
    request.side_effect = httpx.ConnectError("down")
    with pytest.raises(HindsightGatewayError) as network:
        await gateway.health()
    assert network.value.code == "hindsight_unavailable"

    request.side_effect = None
    request.return_value = FakeResponse(value=None, content=b"")
    assert await gateway.health() is None
    request.return_value = FakeResponse(value=None, content=b"x", error=ValueError("bad"))
    with pytest.raises(HindsightGatewayError) as malformed:
        await gateway.health()
    assert malformed.value.code == "hindsight_invalid_response"

    request.return_value = FakeResponse(value={"ok": True})
    await gateway.invalidate_memory("a/b", "m/1", "reason")
    assert "%2F" in request.await_args.args[1]
    gateway.client.aclose = AsyncMock()
    await gateway.close()
    gateway.client.aclose.assert_awaited_once()


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


def test_key_bootstrap_create_existing_repair_and_mismatch(tmp_path: Path) -> None:
    public = tmp_path / "pub" / "key.pem"
    private = tmp_path / "private" / "key.pem"
    assert bootstrap_keys(str(public), str(private)) == "created"
    assert bootstrap_keys(str(public), str(private)) == "existing"
    public.unlink()
    assert bootstrap_keys(str(public), str(private)) == "repaired-public-key"
    public.write_text("wrong")
    with pytest.raises(RuntimeError, match="do not match"):
        bootstrap_keys(str(public), str(private))
    public.unlink()
    private.unlink()
    public.parent.mkdir(exist_ok=True)
    public.write_text("orphan")
    with pytest.raises(RuntimeError, match="public key exists without"):
        bootstrap_keys(str(public), str(private))


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
    assert where == "status <> 'review_in_progress'"
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
    assert where == "status <> 'review_in_progress' AND reason IN (?,?,?,?,?,?,?)"
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
            ("memory_router.app:app",),
            {"host": str(IPv4Address(0)), "port": 8891, "access_log": False},
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
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
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
    assert "sweeper failed" in capsys.readouterr().err
