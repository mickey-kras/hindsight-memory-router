from __future__ import annotations

import asyncio
import multiprocessing
import runpy
import time
from functools import partial
from typing import Any
from unittest.mock import AsyncMock

import pytest
from pebble import ProcessPool

from memory_router import scan_executor
from memory_router.errors import HttpError
from memory_router.security import SafetyResult


@pytest.fixture
def probe() -> dict[str, Any]:
    return runpy.run_path("tests/integration/recall-review-batches.py")["main"].__globals__


@pytest.mark.parametrize("delay_seconds", [8, 14])
async def test_probe_waits_for_delayed_spawn_then_runs_real_duplicate_checks(
    probe: dict[str, Any], monkeypatch: pytest.MonkeyPatch, delay_seconds: int
) -> None:
    scan_executor.shutdown_scan_executor()
    monkeypatch.setattr(
        scan_executor,
        "_new_scan_executor",
        lambda: ProcessPool(
            max_workers=1,
            context=multiprocessing.get_context("spawn"),
            initializer=partial(time.sleep, delay_seconds),
        ),
    )
    monkeypatch.setenv("QUARANTINE_DATABASE_URL", "sqlite:unused.db")
    attempts: list[str] = []
    scan = probe["scan_recalled"]

    async def observe(
        value: dict[str, Any], *, reviewed_result_positions: frozenset[int] | None = None
    ) -> SafetyResult:
        try:
            result = await scan(value, reviewed_result_positions=reviewed_result_positions)
        except HttpError as exc:
            attempts.append(exc.message)
            raise
        attempts.append("ready")
        return result

    monkeypatch.setitem(probe, "scan_recalled", observe)
    await probe["main"]()
    assert len(attempts) >= 2
    assert attempts[-1] == "ready"
    assert attempts.count("recall safety scan timed out") >= 1
    assert set(attempts) == {"ready", "recall safety scan timed out"}
    assert scan_executor._SCAN_EXECUTOR is None


@pytest.mark.parametrize("stage", ["startup", "verification", "success"])
async def test_probe_always_closes_scanner(
    probe: dict[str, Any], monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    warm = AsyncMock(side_effect=RuntimeError("startup") if stage == "startup" else None)
    verify = AsyncMock(
        side_effect=RuntimeError("verification") if stage == "verification" else None
    )
    close = AsyncMock()
    monkeypatch.setitem(probe, "warm_scanner", warm)
    monkeypatch.setitem(probe, "verify_score_certification", AsyncMock())
    monkeypatch.setitem(probe, "verify_database", verify)
    monkeypatch.setitem(probe, "shutdown_scan_executor_async", close)
    if stage == "success":
        await probe["main"]()
    else:
        with pytest.raises(RuntimeError, match=stage):
            await probe["main"]()
    close.assert_awaited_once()
    assert verify.await_count == (0 if stage == "startup" else 1)


@pytest.mark.parametrize(
    "message", ["recall safety scanner is busy", "recall safety scanner worker failed"]
)
async def test_warmup_does_not_retry_other_scanner_failures(
    probe: dict[str, Any], monkeypatch: pytest.MonkeyPatch, message: str
) -> None:
    error = HttpError(503, "recall_scan_unavailable", message)
    scan = AsyncMock(side_effect=error)
    monkeypatch.setitem(probe, "start_scan_executor", lambda: None)
    monkeypatch.setitem(probe, "scan_recalled", scan)
    with pytest.raises(HttpError) as actual:
        await probe["warm_scanner"]()
    assert actual.value is error
    scan.assert_awaited_once()


async def test_warmup_has_an_overall_deadline(
    probe: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def stalled_scan(value: dict[str, Any]) -> SafetyResult:
        await asyncio.Event().wait()
        return SafetyResult()

    monkeypatch.setitem(probe, "SCANNER_STARTUP_SECONDS", 0.05)
    monkeypatch.setitem(probe, "start_scan_executor", lambda: None)
    monkeypatch.setitem(probe, "scan_recalled", stalled_scan)
    with pytest.raises(TimeoutError):
        await probe["warm_scanner"]()
