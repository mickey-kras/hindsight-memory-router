from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import memory_router.app as app_module
from memory_router.logging import LOG_THROTTLE_INTERVAL_SECONDS, log_event
from memory_router.logging_contract import sanitize_fields, sanitize_output_field

PHASES = ("session-prune", "review-recovery", "expiry", "event-retention")
SENSITIVE = "credential=secret payload=private /local/path"


def install_phases(
    monkeypatch: pytest.MonkeyPatch,
    calls: list[str],
    fail: frozenset[str] = frozenset(),
    block: str | None = None,
    entered: asyncio.Event | None = None,
) -> tuple[app_module.Runtime, dict[str, AsyncMock], Mock]:
    runtime = app_module.Runtime()
    runtime.repository = SimpleNamespace()
    operations: dict[str, AsyncMock] = {}

    def operation(phase: str) -> Callable[..., Awaitable[int]]:
        async def run(*_: object) -> int:
            calls.append(phase)
            if phase == block:
                assert entered is not None
                entered.set()
                await asyncio.Event().wait()
            if phase in fail:
                raise RuntimeError(SENSITIVE)
            return 0

        return run

    for phase in PHASES:
        operations[phase] = AsyncMock(side_effect=operation(phase))
    runtime.human_auth = SimpleNamespace(store=SimpleNamespace(prune=operations[PHASES[0]]))
    monkeypatch.setattr(app_module, "recover_interrupted", operations[PHASES[1]])
    monkeypatch.setattr(app_module, "sweep_expired", operations[PHASES[2]])
    monkeypatch.setattr(app_module, "prune_events_before", operations[PHASES[3]])
    failures = Mock()
    monkeypatch.setattr(app_module.metrics, "record_sweeper_failure", failures)
    monkeypatch.setattr(app_module, "iso_now", lambda: "2026-10-14T12:00:00.000Z")
    return runtime, operations, failures


def stop_after_iterations(monkeypatch: pytest.MonkeyPatch, iterations: int) -> list[int]:
    sleeps: list[int] = []

    async def sleep(interval: int) -> None:
        sleeps.append(interval)
        if len(sleeps) > iterations:
            raise asyncio.CancelledError

    monkeypatch.setattr(app_module.asyncio, "sleep", sleep)
    return sleeps


@pytest.mark.parametrize("phase", PHASES)
async def test_each_failed_phase_preserves_independent_work_and_retries(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, phase: str
) -> None:
    calls: list[str] = []
    runtime, _, failures = install_phases(monkeypatch, calls, frozenset({phase}))
    sleeps = stop_after_iterations(monkeypatch, 2)
    with pytest.raises(asyncio.CancelledError):
        await runtime._sweep_loop(7, 3, "events.jsonl")
    expected = [item for item in PHASES if not (phase == "review-recovery" and item == "expiry")]
    assert calls == expected * 2
    assert sleeps == [7, 7, 7]
    assert failures.call_count == 2
    records = [record for record in caplog.records if record.msg == "quarantine_sweeper_failed"]
    assert len(records) == 1
    record = records[0]
    assert record.maintenance_phase == phase
    assert record.operation == "quarantine_maintenance"
    assert record.error_kind == "unexpected"
    assert record.error_fingerprint == "RuntimeError"
    assert record.outcome == "failed"
    assert record.exc_info is None
    formatter = next(
        handler.formatter
        for handler in app_module.logger.parent.handlers
        if handler.formatter is not None
    )
    rendered = formatter.format(record)
    assert json.loads(rendered)["maintenance_phase"] == phase
    assert SENSITIVE not in rendered
    assert SENSITIVE not in caplog.text


@pytest.mark.parametrize(
    "failed",
    [
        ("session-prune", "review-recovery", "event-retention"),
        ("session-prune", "expiry", "event-retention"),
    ],
)
async def test_multiple_phase_failures_count_one_iteration_and_log_each_phase(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, failed: tuple[str, ...]
) -> None:
    calls: list[str] = []
    runtime, _, failures = install_phases(monkeypatch, calls, frozenset(failed))
    stop_after_iterations(monkeypatch, 1)
    with pytest.raises(asyncio.CancelledError):
        await runtime._sweep_loop(5, 1)
    expected = [
        phase for phase in PHASES if not ("review-recovery" in failed and phase == "expiry")
    ]
    assert calls == expected
    failures.assert_called_once_with()
    records = [record for record in caplog.records if record.msg == "quarantine_sweeper_failed"]
    assert [record.maintenance_phase for record in records] == list(failed)


async def test_successful_iteration_preserves_arguments_and_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    runtime, operations, failures = install_phases(monkeypatch, calls)
    stop_after_iterations(monkeypatch, 1)
    before = datetime.now(UTC) - timedelta(days=9)
    with pytest.raises(asyncio.CancelledError):
        await runtime._sweep_loop(5, 9, "archive.jsonl")
    after = datetime.now(UTC) - timedelta(days=9)
    assert calls == list(PHASES)
    failures.assert_not_called()
    operations["session-prune"].assert_awaited_once_with()
    operations["review-recovery"].assert_awaited_once_with(
        runtime.repository, "2026-10-14T12:00:00.000Z", runtime.review_stale_seconds
    )
    operations["expiry"].assert_awaited_once_with(runtime.repository, "2026-10-14T12:00:00.000Z")
    args = operations["event-retention"].await_args.args
    assert args[0] is runtime.repository
    assert args[2:] == ("2026-10-14T12:00:00.000Z", "archive.jsonl")
    cutoff = datetime.fromisoformat(args[1])
    assert before - timedelta(milliseconds=1) <= cutoff <= after


@pytest.mark.parametrize("retention", [0, -1])
async def test_disabled_optional_phases_still_recover_before_expiry(
    monkeypatch: pytest.MonkeyPatch, retention: int
) -> None:
    calls: list[str] = []
    runtime, _, failures = install_phases(monkeypatch, calls)
    runtime.human_auth = None
    stop_after_iterations(monkeypatch, 1)
    with pytest.raises(asyncio.CancelledError):
        await runtime._sweep_loop(5, retention)
    assert calls == ["review-recovery", "expiry"]
    failures.assert_not_called()


@pytest.mark.parametrize("phase", ("sleep", *PHASES))
async def test_cancellation_stops_at_current_phase_without_failure_diagnostics(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, phase: str
) -> None:
    calls: list[str] = []
    entered = asyncio.Event()
    runtime, _, failures = install_phases(monkeypatch, calls, block=phase, entered=entered)

    async def sleep(_: int) -> None:
        if phase == "sleep":
            entered.set()
            await asyncio.Event().wait()

    monkeypatch.setattr(app_module.asyncio, "sleep", sleep)
    task = asyncio.create_task(runtime._sweep_loop(5, 1))
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == ([] if phase == "sleep" else list(PHASES[: PHASES.index(phase) + 1]))
    failures.assert_not_called()
    assert not any(record.msg == "quarantine_sweeper_failed" for record in caplog.records)


@pytest.mark.parametrize(
    ("failed", "blocked", "expected"),
    [
        ("session-prune", "review-recovery", ["session-prune", "review-recovery"]),
        ("session-prune", "expiry", ["session-prune", "review-recovery", "expiry"]),
        (
            "review-recovery",
            "event-retention",
            ["session-prune", "review-recovery", "event-retention"],
        ),
    ],
)
async def test_cancellation_after_failure_preserves_existing_accounting(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failed: str,
    blocked: str,
    expected: list[str],
) -> None:
    calls: list[str] = []
    entered = asyncio.Event()
    runtime, _, failures = install_phases(monkeypatch, calls, frozenset({failed}), blocked, entered)
    stop_after_iterations(monkeypatch, 1)
    task = asyncio.create_task(runtime._sweep_loop(5, 1))
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == expected
    failures.assert_called_once_with()
    records = [record for record in caplog.records if record.msg == "quarantine_sweeper_failed"]
    assert [record.maintenance_phase for record in records] == [failed]


async def test_expiry_resumes_when_recovery_succeeds_on_next_iteration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    runtime, operations, failures = install_phases(monkeypatch, calls)
    original = operations["review-recovery"].side_effect
    recovery_calls = 0

    async def recover(*args: object) -> int:
        nonlocal recovery_calls
        recovery_calls += 1
        if recovery_calls == 1:
            calls.append("review-recovery")
            raise RuntimeError(SENSITIVE)
        return await original(*args)

    operations["review-recovery"].side_effect = recover
    stop_after_iterations(monkeypatch, 2)
    with pytest.raises(asyncio.CancelledError):
        await runtime._sweep_loop(5, 1)
    assert calls == ["session-prune", "review-recovery", "event-retention", *PHASES]
    failures.assert_called_once_with()


@pytest.mark.parametrize("value", [SENSITIVE, "unknown-phase", [], None])
def test_maintenance_phase_diagnostics_drop_unregistered_values(value: object) -> None:
    assert "maintenance_phase" not in sanitize_fields({"maintenance_phase": value})
    assert sanitize_output_field("maintenance_phase", value) is None


def test_phase_throttling_keeps_independent_suppressed_counts(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    now = 100.0
    monkeypatch.setattr("memory_router.logging.time.monotonic", lambda: now)

    def emit(phase: str) -> None:
        log_event(
            app_module.logger,
            "error",
            "quarantine_sweeper_failed",
            maintenance_phase=phase,
            operation="quarantine_maintenance",
            error_kind="unexpected",
        )

    for phase in PHASES:
        emit(phase)
        emit(phase)
    now += LOG_THROTTLE_INTERVAL_SECONDS
    for phase in PHASES:
        emit(phase)
    records = [record for record in caplog.records if record.msg == "quarantine_sweeper_failed"]
    assert [record.maintenance_phase for record in records] == list(PHASES) * 2
    assert all(record.suppressed == 1 for record in records[4:])


def test_other_events_keep_existing_throttle_buckets(caplog: pytest.LogCaptureFixture) -> None:
    for phase in PHASES:
        log_event(
            app_module.logger,
            "error",
            "request_failed",
            maintenance_phase=phase,
            error_kind="unexpected",
        )
    assert sum(record.msg == "request_failed" for record in caplog.records) == 1


async def test_uninitialized_repository_still_fails_before_sleep_or_maintenance(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[str] = []
    runtime, _, failures = install_phases(monkeypatch, calls)
    runtime.repository = None
    sleeps = stop_after_iterations(monkeypatch, 1)
    with pytest.raises(RuntimeError, match="repository is not initialized"):
        await runtime._sweep_loop(5, 1)
    assert sleeps == []
    assert calls == []
    failures.assert_not_called()
    assert not any(record.msg == "quarantine_sweeper_failed" for record in caplog.records)


async def test_sleep_failure_still_propagates_without_maintenance_diagnostics(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[str] = []
    runtime, _, failures = install_phases(monkeypatch, calls)
    monkeypatch.setattr(
        app_module.asyncio, "sleep", AsyncMock(side_effect=RuntimeError("sleep failed"))
    )
    with pytest.raises(RuntimeError, match="sleep failed"):
        await runtime._sweep_loop(5, 1)
    assert calls == []
    failures.assert_not_called()
    assert not any(record.msg == "quarantine_sweeper_failed" for record in caplog.records)
