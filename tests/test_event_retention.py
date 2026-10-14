from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from memory_router import maintenance
from memory_router.app import Runtime
from memory_router.db import SqliteDatabase, initialize_schema
from memory_router.repository import QuarantineRepository

CUTOFF = "2026-01-01T00:00:00Z"
NOW = "2026-02-01T00:00:00Z"
APPEND_EXPORT = maintenance.append_event_export


@pytest.fixture
async def repository(tmp_path: Path) -> AsyncIterator[QuarantineRepository]:
    database = SqliteDatabase(str(tmp_path / "retention.db"))
    await database.initialize()
    await initialize_schema(database)
    try:
        yield QuarantineRepository(database)
    finally:
        await database.close()


async def seed_events(repository: QuarantineRepository, count: int = 2) -> list[dict[str, str]]:
    start = datetime(2025, 1, 1, tzinfo=UTC)
    rows = [
        {
            "event_id": f"event-{index}",
            "quarantine_id": "q1",
            "occurred_at": (start + timedelta(seconds=index)).isoformat().replace("+00:00", "Z"),
            "event_type": "quarantined",
            "details": '{"reason":"unknown_writer"}',
        }
        for index in range(count)
    ]
    async with repository.db.transaction() as tx:
        for row in rows:
            await tx.execute("INSERT INTO quarantine_events VALUES(?,?,?,?,?)", tuple(row.values()))
    return rows


async def stored_events(repository: QuarantineRepository) -> list[dict[str, Any]]:
    async with repository.db.transaction() as tx:
        return await tx.fetchall("SELECT * FROM quarantine_events ORDER BY occurred_at")


def exported_events(path: Path) -> list[dict[str, str]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class BlockedExport:
    def __init__(self, error: OSError | None = None) -> None:
        self.loop = asyncio.get_running_loop()
        self.started = asyncio.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.thread_id: int | None = None
        self.error = error

    def __call__(self, path: str, rows: list[dict[str, Any]]) -> None:
        self.thread_id = threading.get_ident()
        self.loop.call_soon_threadsafe(self.started.set)
        try:
            if not self.release.wait(timeout=5):
                raise TimeoutError("export test barrier was not released")
            if self.error is not None:
                raise self.error
            APPEND_EXPORT(path, rows)
        finally:
            self.finished.set()


@pytest.mark.asyncio
async def test_slow_export_keeps_loop_running_and_defers_delete_until_file_close(
    repository: QuarantineRepository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = await seed_events(repository)
    export_path = tmp_path / "events.jsonl"
    worker = BlockedExport()
    monkeypatch.setattr(maintenance, "append_event_export", worker)
    database = repository.db
    assert isinstance(database, SqliteDatabase) and database.connection is not None
    deleted: list[str] = []
    deleted_after_close: list[bool] = []

    def trace(sql: str) -> None:
        if sql.startswith("DELETE FROM quarantine_events"):
            deleted.append(sql)
            deleted_after_close.append(worker.finished.is_set())

    await database.connection.set_trace_callback(trace)
    prune = asyncio.create_task(
        maintenance.prune_events_before(repository, CUTOFF, NOW, str(export_path))
    )
    try:
        await asyncio.wait_for(worker.started.wait(), 2)
        await asyncio.wait_for(asyncio.sleep(0), 1)
        assert worker.thread_id != threading.get_ident()
        assert not prune.done()
        assert not deleted
        assert not export_path.exists()
    finally:
        worker.release.set()
        result = await asyncio.wait_for(prune, 2)
    assert result == len(rows)
    assert exported_events(export_path) == rows
    assert len(deleted) == len(rows) and all(deleted_after_close)


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_export", [False, True])
async def test_repeated_cancellation_drains_export_before_rollback_and_unlock(
    repository: QuarantineRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_export: bool,
) -> None:
    rows = await seed_events(repository)
    export_path = tmp_path / "events.jsonl"
    error = OSError("export disk unavailable") if fail_export else None
    worker = BlockedExport(error)
    monkeypatch.setattr(maintenance, "append_event_export", worker)
    prune = asyncio.create_task(
        maintenance.prune_events_before(repository, CUTOFF, NOW, str(export_path))
    )
    ping: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(worker.started.wait(), 2)
        prune.cancel("first cancellation")
        await asyncio.sleep(0)
        prune.cancel("second cancellation")
        ping = asyncio.create_task(repository.db.ping())
        await asyncio.sleep(0)
        assert not prune.done()
        assert not ping.done()
        assert not worker.finished.is_set()
    finally:
        worker.release.set()
        with pytest.raises(asyncio.CancelledError) as cancelled:
            await asyncio.wait_for(prune, 2)
        if ping is not None:
            await asyncio.wait_for(ping, 2)
    assert cancelled.value.args == ("first cancellation",)
    assert cancelled.value.__cause__ is error
    assert worker.finished.is_set()
    assert await stored_events(repository) == rows
    if not fail_export:
        assert exported_events(export_path) == rows
    monkeypatch.setattr(maintenance, "append_event_export", APPEND_EXPORT)
    assert await maintenance.prune_events_before(repository, CUTOFF, NOW, str(export_path)) == 2
    assert exported_events(export_path) == (rows if fail_export else rows + rows)


@pytest.mark.asyncio
async def test_failed_append_preserves_batch_and_retry_duplicates_completed_record(
    repository: QuarantineRepository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = await seed_events(repository)
    export_path = tmp_path / "events.jsonl"

    def fail_after_record(path: str, selected: list[dict[str, Any]]) -> None:
        APPEND_EXPORT(path, selected[:1])
        raise OSError("write failed after a complete record")

    monkeypatch.setattr(maintenance, "append_event_export", fail_after_record)
    with pytest.raises(OSError, match="write failed"):
        await maintenance.prune_events_before(repository, CUTOFF, NOW, str(export_path))
    assert await stored_events(repository) == rows
    assert exported_events(export_path) == rows[:1]
    monkeypatch.setattr(maintenance, "append_event_export", APPEND_EXPORT)
    assert await maintenance.prune_events_before(repository, CUTOFF, NOW, str(export_path)) == 2
    assert exported_events(export_path) == rows[:1] + rows
    (summary,) = await stored_events(repository)
    assert summary["event_type"] == "retention_pruned"
    assert json.loads(summary["details"]) == {"pruned_events": 2, "older_than": CUTOFF}


@pytest.mark.asyncio
async def test_database_failure_after_append_rolls_back_deletions_and_retry_duplicates_batch(
    repository: QuarantineRepository, tmp_path: Path
) -> None:
    rows = await seed_events(repository)
    export_path = tmp_path / "events.jsonl"
    async with repository.db.transaction() as tx:
        await tx.execute(
            "CREATE TRIGGER fail_second_delete BEFORE DELETE ON quarantine_events "
            "WHEN OLD.event_id='event-1' BEGIN SELECT RAISE(ABORT, 'delete failed'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="delete failed"):
        await maintenance.prune_events_before(repository, CUTOFF, NOW, str(export_path))
    assert await stored_events(repository) == rows
    assert exported_events(export_path) == rows
    async with repository.db.transaction() as tx:
        await tx.execute("DROP TRIGGER fail_second_delete")
    assert await maintenance.prune_events_before(repository, CUTOFF, NOW, str(export_path)) == 2
    assert exported_events(export_path) == rows + rows
    (summary,) = await stored_events(repository)
    assert summary["event_type"] == "retention_pruned"


@pytest.mark.asyncio
async def test_export_batches_are_bounded_serial_and_keep_cutoff_and_recent_events(
    repository: QuarantineRepository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = await seed_events(repository, 1001)
    async with repository.db.transaction() as tx:
        for event_id, at in (("cutoff", CUTOFF), ("recent", NOW)):
            await tx.execute(
                "INSERT INTO quarantine_events VALUES(?,?,?,?,?)",
                (event_id, "q1", at, "quarantined", "{}"),
            )
    export_path = tmp_path / "events.jsonl"
    batch_sizes: list[int] = []
    active = 0
    maximum_active = 0

    def append(path: str, selected: list[dict[str, Any]]) -> None:
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        try:
            assert threading.get_ident() != loop_thread
            batch_sizes.append(len(selected))
            APPEND_EXPORT(path, selected)
        finally:
            active -= 1

    loop_thread = threading.get_ident()
    monkeypatch.setattr(maintenance, "append_event_export", append)
    assert await maintenance.prune_events_before(repository, CUTOFF, NOW, str(export_path)) == 1001
    assert batch_sizes == [1000, 1]
    assert maximum_active == 1 and active == 0
    assert exported_events(export_path) == rows
    remaining = await stored_events(repository)
    assert {row["event_id"] for row in remaining if row["event_type"] == "quarantined"} == {
        "cutoff",
        "recent",
    }
    (summary,) = [row for row in remaining if row["event_type"] == "retention_pruned"]
    assert json.loads(summary["details"]) == {"pruned_events": 1001, "older_than": CUTOFF}


@pytest.mark.asyncio
async def test_retention_without_export_still_prunes_and_records_summary(
    repository: QuarantineRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seed_events(repository)

    def unexpected_export(path: str, rows: list[dict[str, Any]]) -> None:
        pytest.fail("retention without an export path must not append")

    monkeypatch.setattr(maintenance, "append_event_export", unexpected_export)
    assert await maintenance.prune_events_before(repository, CUTOFF, NOW) == 2
    (summary,) = await stored_events(repository)
    assert summary["event_type"] == "retention_pruned"
    assert await maintenance.prune_events_before(repository, CUTOFF, NOW) == 0
    assert await stored_events(repository) == [summary]


@pytest.mark.asyncio
async def test_shutdown_drains_export_before_closing_database(
    repository: QuarantineRepository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = await seed_events(repository)
    worker = BlockedExport()
    monkeypatch.setattr(maintenance, "append_event_export", worker)
    export_path = tmp_path / "events.jsonl"
    runtime = Runtime()
    runtime.repository = repository
    runtime.sweeper = asyncio.create_task(
        maintenance.prune_events_before(repository, CUTOFF, NOW, str(export_path))
    )
    database = repository.db
    original_close = database.close
    closed = asyncio.Event()

    async def close() -> None:
        assert worker.finished.is_set()
        assert await stored_events(repository) == rows
        await original_close()
        closed.set()

    monkeypatch.setattr(database, "close", close)
    stop: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(worker.started.wait(), 2)
        stop = asyncio.create_task(runtime.stop())
        await asyncio.sleep(0)
        assert not stop.done()
        assert not closed.is_set()
    finally:
        worker.release.set()
        if stop is None:
            stop = asyncio.create_task(runtime.stop())
        await asyncio.wait_for(stop, 2)
        monkeypatch.setattr(database, "close", original_close)
    assert closed.is_set()
    assert exported_events(export_path) == rows
    assert runtime.repository is None and runtime.sweeper is None
