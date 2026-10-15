from __future__ import annotations

import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import memory_router.app as app_module
from memory_router.db import create_database
from memory_router.repository import QuarantineRepository

OLD = "2000-01-01T00:00:00.000Z"


async def verify_phases(path: Path, failed_phase: str) -> None:
    database = await create_database(f"sqlite:{path}")
    repository = QuarantineRepository(database)
    runtime = app_module.Runtime()
    runtime.repository = repository
    sleeps = 0

    async def sleep(interval: int) -> None:
        nonlocal sleeps
        assert interval == 5
        sleeps += 1
        if sleeps > 1:
            raise asyncio.CancelledError

    try:
        async with database.transaction() as tx:
            for qid, status, expires in (
                ("expired-pending", "pending", OLD),
                ("interrupted-review", "review_in_progress", None),
            ):
                await repository.insert_item(
                    tx,
                    {
                        "quarantine_id": qid,
                        "created_at": OLD,
                        "updated_at": OLD,
                        "kind": "retain_request",
                        "reason": "suspicious_content",
                        "sha256": "test-hash",
                        "encrypted": {"v": 1},
                        "status": status,
                        "postpone_count": 0,
                        "requarantine_count": 0,
                        "expires_at": expires,
                    },
                )

        recover = AsyncMock(wraps=app_module.recover_interrupted)
        expiry = AsyncMock(wraps=app_module.sweep_expired)
        failure = RuntimeError("sensitive maintenance failure")
        if failed_phase == "session-prune":
            runtime.human_auth = SimpleNamespace(
                store=SimpleNamespace(prune=AsyncMock(side_effect=failure))
            )
        elif failed_phase == "review-recovery":
            recover.side_effect = failure
        elif failed_phase == "expiry":
            expiry.side_effect = failure
        metrics = Mock()
        with (
            patch.object(app_module.asyncio, "sleep", sleep),
            patch.object(app_module, "recover_interrupted", recover),
            patch.object(app_module, "sweep_expired", expiry),
            patch.object(app_module.metrics, "record_sweeper_failure", metrics),
        ):
            try:
                export_path = (
                    str(path.parent / "missing" / "archive.jsonl")
                    if failed_phase == "event-retention"
                    else None
                )
                await runtime._sweep_loop(5, 1, export_path)
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("sweeper swallowed cancellation")

        assert sleeps == 2
        metrics.assert_called_once_with()
        recover.assert_awaited_once()
        if failed_phase == "review-recovery":
            expiry.assert_not_awaited()
        else:
            expiry.assert_awaited_once()
        pending = await repository.get("expired-pending")
        assert (pending is None) == (failed_phase not in {"review-recovery", "expiry"})
        interrupted = await repository.get("interrupted-review")
        assert interrupted is not None
        assert interrupted["status"] == (
            "review_in_progress" if failed_phase == "review-recovery" else "postponed"
        )
        async with database.transaction() as tx:
            old_events = await tx.fetchall(
                "SELECT event_id FROM quarantine_events WHERE occurred_at=?", (OLD,)
            )
            retention_events = await tx.fetchall(
                "SELECT details FROM quarantine_events WHERE event_type='retention_pruned'"
            )
        assert len(old_events) == (2 if failed_phase == "event-retention" else 0)
        assert len(retention_events) == (0 if failed_phase == "event-retention" else 1)
        if retention_events:
            assert json.loads(retention_events[0]["details"])["pruned_events"] == 2
        await database.ping()
    finally:
        await repository.close()


async def main(directory: Path) -> None:
    for phase in ("session-prune", "review-recovery", "expiry", "event-retention"):
        await verify_phases(directory / f"{phase}.db", phase)


with TemporaryDirectory() as directory:
    asyncio.run(main(Path(directory)))
