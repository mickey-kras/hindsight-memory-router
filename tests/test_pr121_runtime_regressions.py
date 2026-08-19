from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from memory_router import app as app_module


@pytest.mark.asyncio
async def test_postgres_runtime_keeps_auth_failure_limiter_in_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QUARANTINE_DATABASE_URL", "postgresql://db")
    monkeypatch.setenv("QUARANTINE_SWEEP_INTERVAL_SECONDS", "0")
    monkeypatch.setattr(app_module, "assert_no_private_key_environment", lambda: None)
    monkeypatch.setattr(app_module, "assert_auth_environment", lambda: None)
    monkeypatch.setattr(app_module, "assert_deployment_mode", lambda _: None)

    primary_db = SimpleNamespace()
    monkeypatch.setattr(app_module, "create_database", AsyncMock(return_value=primary_db))
    monkeypatch.setattr(app_module, "validate_storage", AsyncMock())
    monkeypatch.setattr(app_module, "recover_interrupted", AsyncMock())
    repository = SimpleNamespace(close=AsyncMock())
    monkeypatch.setattr(app_module, "QuarantineRepository", lambda _: repository)

    rate_db = SimpleNamespace(initialize=AsyncMock(), close=AsyncMock())
    monkeypatch.setattr(app_module, "PostgresDatabase", lambda *args, **kwargs: rate_db)
    shared_limiter = SimpleNamespace(initialize=AsyncMock())
    monkeypatch.setattr(app_module, "PostgresRateLimiter", lambda _: shared_limiter)

    store = object()
    hindsight = SimpleNamespace(close=AsyncMock())
    registry = SimpleNamespace(writers={})
    monkeypatch.setattr(app_module, "QuarantineStore", lambda *args: store)
    monkeypatch.setattr(app_module, "HindsightGateway", lambda *args: hindsight)
    monkeypatch.setattr(app_module, "load_registry", lambda _: registry)
    monkeypatch.setattr(app_module, "HindsightLimits", lambda *args: object())
    monkeypatch.setattr(app_module, "RouterPolicy", lambda *args: object())
    monkeypatch.setattr(app_module, "QuarantineAdminService", lambda *args: object())
    monkeypatch.setattr(app_module, "AuthFailureAuditor", lambda _: object())

    runtime = app_module.Runtime()
    await runtime.start()
    assert runtime.quarantine_limiter is shared_limiter
    assert isinstance(runtime.auth_limiter, app_module.InMemoryRateLimiter)
    await runtime.stop()
