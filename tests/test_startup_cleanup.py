from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import aiosqlite
import pytest

from memory_router import app as app_module
from memory_router import db as db_module
from memory_router.config import RouterSettings
from memory_router.hindsight import HindsightGateway
from memory_router.key_wrap import SidecarWrapProvider
from tests.test_crypto_db import keypair


@pytest.fixture
def connections(monkeypatch: pytest.MonkeyPatch) -> list[aiosqlite.Connection]:
    connections: list[aiosqlite.Connection] = []
    connect = aiosqlite.connect

    def capture(path: str) -> aiosqlite.Connection:
        connection = connect(path)
        connections.append(connection)
        return connection

    monkeypatch.setattr(db_module.aiosqlite, "connect", capture)
    return connections


async def assert_closed(connection: aiosqlite.Connection) -> None:
    await asyncio.to_thread(connection._thread.join, 1)
    assert not connection._thread.is_alive()
    with pytest.raises(ValueError, match="no active connection"):
        await connection.execute("SELECT 1")


@pytest.fixture
def settings(tmp_path: Path) -> RouterSettings:
    return RouterSettings(
        QUARANTINE_DATABASE_URL=f"sqlite:{tmp_path / 'quarantine.db'}",
        QUARANTINE_PUBLIC_KEY=keypair()[0],
        QUARANTINE_SWEEP_INTERVAL_SECONDS=0,
    )


async def test_invalid_key_startup_closes_sqlite_and_allows_successful_retry(
    settings: RouterSettings,
    connections: list[aiosqlite.Connection],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = app_module.Runtime(settings.model_copy(update={"quarantine_public_key": "invalid"}))
    monkeypatch.setattr(app_module, "runtime", runtime)
    for _ in range(2):
        with pytest.raises(ValueError):
            async with app_module.lifespan(app_module.app):
                pytest.fail("invalid public key reached a running application")
        await assert_closed(connections[-1])
        assert runtime.repository is None

    runtime.configure(settings)
    for _ in range(2):
        await runtime.start()
        assert runtime.repository is not None
        await runtime.repository.ping()
        with pytest.raises(RuntimeError, match="already started"):
            await runtime.start()
        await runtime.stop()
        await runtime.stop()
        await assert_closed(connections[-1])


async def test_late_startup_failure_closes_both_http_clients_and_database(
    settings: RouterSettings,
    connections: list[aiosqlite.Connection],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    registry = tmp_path / "invalid-registry.json"
    registry.write_text("invalid JSON")
    runtime = app_module.Runtime(
        settings.model_copy(
            update={
                "quarantine_wrap_provider": "https-sidecar",
                "quarantine_wrap_sidecar_url": "https://wrap.example",
                "memory_router_registry": str(registry),
            }
        )
    )
    providers: list[SidecarWrapProvider] = []
    gateways: list[HindsightGateway] = []
    build_provider = app_module._build_wrap_provider

    def capture_provider(config: RouterSettings) -> SidecarWrapProvider | None:
        provider = build_provider(config)
        assert provider is not None
        providers.append(provider)
        return provider

    def capture_gateway(
        url: str, key: str | None, timeout: int, max_response_bytes: int
    ) -> HindsightGateway:
        gateway = HindsightGateway(url, key, timeout, max_response_bytes)
        gateways.append(gateway)
        return gateway

    monkeypatch.setattr(app_module, "_build_wrap_provider", capture_provider)
    monkeypatch.setattr(app_module, "HindsightGateway", capture_gateway)
    with pytest.raises(json.JSONDecodeError):
        await runtime.start()

    assert providers[0].client.is_closed
    assert gateways[0].client.is_closed
    await assert_closed(connections[0])


async def test_repeated_startup_cancellation_finishes_cleanup_before_returning(
    settings: RouterSettings,
    connections: list[aiosqlite.Connection],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = app_module.Runtime(settings)
    started = asyncio.Event()
    closing = asyncio.Event()
    release = asyncio.Event()
    close = db_module.SqliteDatabase.close

    async def validate(*_: object) -> None:
        started.set()
        await asyncio.Event().wait()

    async def delayed_close(database: db_module.SqliteDatabase) -> None:
        closing.set()
        await release.wait()
        await close(database)

    with monkeypatch.context() as patch:
        patch.setattr(app_module, "validate_storage", validate)
        patch.setattr(db_module.SqliteDatabase, "close", delayed_close)
        startup = asyncio.create_task(runtime.start())
        await asyncio.wait_for(started.wait(), timeout=2)
        startup.cancel("original cancellation")
        await asyncio.wait_for(closing.wait(), timeout=2)
        startup.cancel("second cancellation")
        await asyncio.sleep(0)
        assert not startup.done()
        release.set()
        with pytest.raises(asyncio.CancelledError, match="original cancellation"):
            await startup

    await assert_closed(connections[0])
    await runtime.start()
    await runtime.stop()
    await assert_closed(connections[1])


@pytest.mark.parametrize("phase", ["permissions", "schema"])
async def test_database_factory_closes_partially_initialized_connection(
    phase: str,
    connections: list[aiosqlite.Connection],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if phase == "permissions":
        failure = PermissionError("permissions unavailable")

        def deny_permissions(*_: object) -> None:
            raise failure

        monkeypatch.setattr(db_module.os, "chmod", deny_permissions)
        error_type = PermissionError
    else:
        monkeypatch.setattr(db_module, "SCHEMA", [*db_module.SCHEMA, "INVALID SQL"])
        error_type = sqlite3.OperationalError

    with pytest.raises(error_type):
        await db_module.create_database(f"sqlite:{tmp_path / 'quarantine.db'}")
    await assert_closed(connections[0])


async def test_cancelled_sqlite_connect_finishes_acquisition_then_closes_worker(
    connections: list[aiosqlite.Connection], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    started = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    connect = sqlite3.connect

    def delayed_connect(path: str, **kwargs: object) -> sqlite3.Connection:
        loop.call_soon_threadsafe(started.set)
        release.wait(timeout=5)
        return connect(path, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", delayed_connect)
    startup = asyncio.create_task(db_module.create_database(f"sqlite:{tmp_path / 'quarantine.db'}"))
    try:
        await asyncio.wait_for(started.wait(), timeout=2)
        startup.cancel("connect cancelled")
        await asyncio.sleep(0)
        startup.cancel("connect cancelled again")
        await asyncio.sleep(0)
        assert not startup.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError, match="connect cancelled"):
        await asyncio.wait_for(startup, timeout=2)
    await assert_closed(connections[0])


async def test_cleanup_failure_preserves_startup_error_and_closes_remaining_resources(
    settings: RouterSettings,
    connections: list[aiosqlite.Connection],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = app_module.Runtime(settings)
    original_error = RuntimeError("registry failure")
    close_error = RuntimeError("gateway cleanup failure")

    def fail_registry(_: str | None) -> None:
        raise original_error

    close = HindsightGateway.close

    async def fail_close(gateway: HindsightGateway) -> None:
        await close(gateway)
        raise close_error

    monkeypatch.setattr(app_module, "load_registry", fail_registry)
    monkeypatch.setattr(HindsightGateway, "close", fail_close)
    with pytest.raises(RuntimeError) as raised:
        await runtime.start()
    assert raised.value is original_error
    assert raised.value.__cause__ is close_error
    await assert_closed(connections[0])


async def test_failed_sweeper_does_not_prevent_closing_other_resources(
    settings: RouterSettings, connections: list[aiosqlite.Connection]
) -> None:
    runtime = app_module.Runtime(settings)
    await runtime.start()
    gateway = runtime.hindsight
    assert gateway is not None
    failure = RuntimeError("sweeper failed")

    async def fail() -> None:
        raise failure

    runtime.sweeper = asyncio.create_task(fail())
    await asyncio.sleep(0)
    with pytest.raises(RuntimeError) as raised:
        await runtime.stop()
    assert raised.value is failure
    assert gateway.client.is_closed
    await assert_closed(connections[0])


async def test_cancelled_scanner_start_finishes_acquisition_before_runtime_cleanup(
    settings: RouterSettings,
    connections: list[aiosqlite.Connection],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = app_module.Runtime(settings)
    started = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    events: list[str] = []

    def start_scanner() -> None:
        loop.call_soon_threadsafe(started.set)
        release.wait(timeout=5)
        events.append("scanner started")

    async def stop_scanner() -> None:
        events.append("scanner stopped")

    async def start_application() -> None:
        async with app_module.lifespan(app_module.app):
            pytest.fail("cancelled startup reached a running application")

    monkeypatch.setattr(app_module, "runtime", runtime)
    monkeypatch.setattr(app_module, "start_scan_executor", start_scanner)
    monkeypatch.setattr(app_module, "shutdown_scan_executor_async", stop_scanner)
    startup = asyncio.create_task(start_application())
    try:
        await asyncio.wait_for(started.wait(), timeout=2)
        startup.cancel()
        await asyncio.sleep(0)
        assert not startup.done()
        assert not events
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(startup, timeout=2)
    assert events == ["scanner started", "scanner stopped"]
    await assert_closed(connections[0])


async def test_postgres_pool_start_failure_closes_primary_even_if_pool_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_error = RuntimeError("pool unavailable")
    close_error = RuntimeError("pool cleanup failed")
    database = SimpleNamespace(dialect="postgres", close=AsyncMock())
    pool = SimpleNamespace(
        initialize=AsyncMock(side_effect=original_error),
        close=AsyncMock(side_effect=close_error),
    )
    monkeypatch.setattr(db_module, "create_database", AsyncMock(return_value=database))
    monkeypatch.setattr(db_module, "PostgresDatabase", lambda *args, **kwargs: pool)
    with pytest.raises(RuntimeError) as raised:
        await db_module.create_backend("postgresql://db")
    assert raised.value is original_error
    assert raised.value.__cause__ is close_error
    database.close.assert_awaited_once()
