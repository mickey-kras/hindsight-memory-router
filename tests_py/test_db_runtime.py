from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from memory_router import db as db_module


def test_database_url_helpers(tmp_path: Path) -> None:
    assert db_module.is_postgres("postgres://x")
    assert db_module.is_postgres("postgresql://x")
    assert not db_module.is_postgres("sqlite:x")
    assert db_module.sqlite_path("sqlite::memory:") == ":memory:"
    assert db_module.sqlite_path("sqlite:///tmp/x") == "/tmp/x"
    assert db_module.sqlite_path("sqlite:/tmp/x") == "/tmp/x"
    assert Path(db_module.sqlite_path("sqlite:relative.db")).is_absolute()
    with pytest.raises(RuntimeError, match="path is required"):
        db_module.sqlite_path("sqlite:")


@pytest.mark.asyncio
async def test_sqlite_database_transactions_schema_and_ping(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "q.db"
    database = db_module.SqliteDatabase(str(path))
    with pytest.raises(RuntimeError, match="not initialized"):
        async with database.transaction():
            pass
    await database.initialize()
    await db_module.initialize_schema(database)
    await database.ping()
    async with database.transaction() as tx:
        assert tx.dialect == "sqlite"
        await tx.execute(
            "INSERT INTO quarantine_events(event_id,quarantine_id,occurred_at,event_type,details) VALUES(?,?,?,?,?)",
            ("1", "q", "now", "x", "{}"),
        )
        assert (
            await tx.fetchone("SELECT event_id FROM quarantine_events WHERE event_id=?", ("1",))
        ) == {"event_id": "1"}
        assert len(await tx.fetchall("SELECT event_id FROM quarantine_events")) == 1
    with pytest.raises(RuntimeError, match="rollback"):
        async with database.transaction() as tx:
            await tx.execute(
                "INSERT INTO quarantine_events(event_id,quarantine_id,occurred_at,event_type,details) VALUES(?,?,?,?,?)",
                ("2", "q", "now", "x", "{}"),
            )
            raise RuntimeError("rollback")
    async with database.transaction() as tx:
        assert (
            await tx.fetchone("SELECT event_id FROM quarantine_events WHERE event_id=?", ("2",))
            is None
        )
    await db_module.validate_storage(database, f"sqlite:{path}")
    await database.close()


@pytest.mark.asyncio
async def test_create_database_sqlite_and_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MEMORY_ROUTER_DEPLOYMENT_MODE", "single")
    database = await db_module.create_database(f"sqlite:{tmp_path / 'created.db'}")
    assert database.dialect == "sqlite"
    await database.close()
    with pytest.raises(RuntimeError, match="must use"):
        await db_module.create_database("mysql://x")


@pytest.mark.asyncio
async def test_validate_storage_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    broken = SimpleNamespace(ping=AsyncMock(side_effect=RuntimeError("down")))
    with pytest.raises(RuntimeError, match="unreachable"):
        await db_module.validate_storage(broken, "postgres://x")

    ok = SimpleNamespace(ping=AsyncMock())
    await db_module.validate_storage(ok, "postgres://x")
    await db_module.validate_storage(ok, "sqlite::memory:")
    path = tmp_path / "x.db"
    path.write_text("x")
    original = db_module.os.access
    monkeypatch.setattr(
        db_module.os,
        "access",
        lambda target, mode: False if str(target) == str(path.parent) else original(target, mode),
    )
    with pytest.raises(RuntimeError, match="not writable"):
        await db_module.validate_storage(ok, f"sqlite:{path}")


class Cursor:
    def __init__(self, one: object = None, many: list[object] | None = None) -> None:
        self.one = one
        self.many = many or []

    async def fetchone(self) -> object:
        return self.one

    async def fetchall(self) -> list[object]:
        return self.many


@pytest.mark.asyncio
async def test_postgres_tx_translation() -> None:
    connection = SimpleNamespace(execute=AsyncMock())
    connection.execute.side_effect = [None, Cursor({"x": 1}), Cursor(many=[{"x": 1}])]
    tx = db_module.PostgresTx(connection)
    assert tx.sql("a=? AND b=?") == "a=%s AND b=%s"
    await tx.execute("UPDATE x SET a=?", (1,))
    assert await tx.fetchone("SELECT ? x", (1,)) == {"x": 1}
    assert await tx.fetchall("SELECT ? x", (1,)) == [{"x": 1}]
    assert "%s" in connection.execute.await_args_list[0].args[0]


@pytest.mark.asyncio
async def test_initialize_schema_postgres_and_existing_columns() -> None:
    class Tx:
        dialect = "postgres"

        def __init__(self) -> None:
            self.calls: list[str] = []
            self.i = 0

        async def execute(self, sql: str, params: object = ()) -> None:
            self.calls.append(sql)

        async def fetchone(self, sql: str, params: object = ()) -> dict[str, int] | None:
            self.i += 1
            return {"present": 1} if self.i == 1 else None

    tx = Tx()

    class Ctx:
        async def __aenter__(self) -> Tx:
            return tx

        async def __aexit__(self, *args: object) -> None:
            return None

    fake = SimpleNamespace(transaction=lambda **kwargs: Ctx())
    await db_module.initialize_schema(fake)
    assert any(
        "information_schema.columns" not in call and "ALTER TABLE" in call for call in tx.calls
    )
