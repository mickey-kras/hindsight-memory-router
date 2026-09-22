from __future__ import annotations

import asyncio
import json
import logging
import multiprocessing
from contextlib import suppress
from threading import BoundedSemaphore, Lock
from typing import Any, Literal, cast

from pebble import ProcessExpired, ProcessPool

from .errors import HttpError
from .hindsight import MAX_FACADE_RESPONSE_BYTES
from .logging import log_event
from .observability import current_request_id
from .security import (
    MAX_CORE_SCAN_SECONDS,
    MAX_FACADE_SCAN_SECONDS,
    MAX_QUERY_SCAN_SECONDS,
    SafetyResult,
    scan_facade_payload,
    scan_query_values,
    scan_recall_body,
    scan_recall_result,
    scan_retain_body,
)

logger = logging.getLogger(__name__)
SCAN_WORKERS = 4
SCAN_CAPACITY = 4
FACADE_SCAN_TASK_SECONDS = MAX_FACADE_SCAN_SECONDS + 1.0
FACADE_SCAN_WAIT_SECONDS = FACADE_SCAN_TASK_SECONDS + 1.0


class _ScannerShutdown(RuntimeError):
    pass


_SCANNER_SHUT_DOWN = "safety scanner shut down"
CORE_SCAN_TASK_SECONDS = MAX_CORE_SCAN_SECONDS + 1.0
QUERY_SCAN_TASK_SECONDS = MAX_CORE_SCAN_SECONDS + MAX_QUERY_SCAN_SECONDS + 1.0
ScanKind = Literal["request", "response", "recall"]


def _new_scan_executor() -> ProcessPool:
    return ProcessPool(
        max_workers=SCAN_WORKERS,
        context=cast(Any, multiprocessing.get_context("spawn")),
    )


_SCAN_EXECUTOR: ProcessPool | None = None
_SCAN_EXECUTOR_LOCK = Lock()
_SCAN_CAPACITY = BoundedSemaphore(value=SCAN_CAPACITY)
_SCAN_GENERATION = 0
_SCAN_SHUTDOWN = False
_SCAN_FUTURES: set[Any] = set()


def scan_unavailable(
    message: str, *, error_kind: str, writer_id: str | None = None, kind: ScanKind = "response"
) -> HttpError:
    operation = "facade_scan" if kind == "response" else f"{kind}_scan"
    log_event(
        logger,
        "warning",
        f"{operation}_failed",
        request_id=current_request_id(),
        operation=operation,
        error_kind=error_kind,
        outcome="failed",
        route_class="openclaw" if kind == "response" else None,
        writer_id=writer_id,
    )
    return HttpError(
        503,
        f"{operation}_unavailable",
        message,
        headers={"Retry-After": "1"},
    )


def _scan_generation() -> int:
    with _SCAN_EXECUTOR_LOCK:
        return _SCAN_GENERATION


def _scan_stopped(generation: int) -> bool:
    with _SCAN_EXECUTOR_LOCK:
        return _SCAN_SHUTDOWN or generation != _SCAN_GENERATION


def _get_scan_executor(expected_generation: int | None = None) -> ProcessPool:
    global _SCAN_EXECUTOR
    stale = None
    with _SCAN_EXECUTOR_LOCK:
        if _SCAN_SHUTDOWN:
            raise _ScannerShutdown(_SCANNER_SHUT_DOWN)
        if expected_generation is not None and expected_generation != _SCAN_GENERATION:
            raise _ScannerShutdown(_SCANNER_SHUT_DOWN)
        if _SCAN_EXECUTOR is None or not _SCAN_EXECUTOR.active:
            stale = _SCAN_EXECUTOR
            _SCAN_EXECUTOR = _new_scan_executor()
        executor = _SCAN_EXECUTOR
    if stale is not None:
        with suppress(Exception):
            stale.stop()  # type: ignore[no-untyped-call]
        with suppress(Exception):
            stale.join(timeout=5)
    return executor


async def _get_scan_executor_async(expected_generation: int) -> ProcessPool:
    return await asyncio.to_thread(_get_scan_executor, expected_generation)


def start_scan_executor() -> None:
    global _SCAN_CAPACITY, _SCAN_SHUTDOWN
    with _SCAN_EXECUTOR_LOCK:
        restarting = _SCAN_SHUTDOWN
        _SCAN_SHUTDOWN = False
        if restarting:
            _SCAN_CAPACITY = BoundedSemaphore(value=SCAN_CAPACITY)
            _SCAN_FUTURES.clear()
    executor = _get_scan_executor()
    if not executor.active:
        raise RuntimeError("safety scanner failed to start")


def _acquire_scan_capacity() -> tuple[int, BoundedSemaphore] | None:
    with _SCAN_EXECUTOR_LOCK:
        if _SCAN_SHUTDOWN:
            raise _ScannerShutdown(_SCANNER_SHUT_DOWN)
        capacity = _SCAN_CAPACITY
        if not capacity.acquire(blocking=False):
            return None
        return _SCAN_GENERATION, capacity


def shutdown_scan_executor() -> None:
    global _SCAN_EXECUTOR, _SCAN_GENERATION, _SCAN_SHUTDOWN
    with _SCAN_EXECUTOR_LOCK:
        _SCAN_SHUTDOWN = True
        _SCAN_GENERATION += 1
        executor = _SCAN_EXECUTOR
        _SCAN_EXECUTOR = None
        futures = tuple(_SCAN_FUTURES)
    for future in futures:
        with suppress(Exception):
            future.cancel()
    if executor is not None:
        with suppress(Exception):
            executor.stop()  # type: ignore[no-untyped-call]
        with suppress(Exception):
            executor.join(timeout=5)


async def shutdown_scan_executor_async() -> None:
    await asyncio.to_thread(shutdown_scan_executor)


def _scanner_shutdown(writer_id: str | None, kind: ScanKind) -> HttpError:
    return scan_unavailable(
        f"{kind} safety scanner is shut down", error_kind="shutdown", writer_id=writer_id, kind=kind
    )


async def _scan_in_worker(  # NOSONAR
    value: Any, *, kind: ScanKind, task_seconds: float, wait_seconds: float, writer_id: str | None
) -> SafetyResult:
    try:
        admission = _acquire_scan_capacity()
    except _ScannerShutdown as exc:
        raise _scanner_shutdown(writer_id, kind) from exc
    if admission is None:
        raise scan_unavailable(
            f"{kind} safety scanner is busy", error_kind="capacity", writer_id=writer_id, kind=kind
        )
    generation, capacity = admission
    try:
        payload = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if kind == "response" and len(payload) > MAX_FACADE_RESPONSE_BYTES:
            raise scan_unavailable(
                "response exceeded safety scan limits",
                error_kind="response-too-large",
                writer_id=writer_id,
                kind=kind,
            )
        executor = await _get_scan_executor_async(generation)
        scanner = {
            "response": scan_facade_payload,
            "request": _scan_request_payload,
            "recall": _scan_recalled_payload,
        }[kind]
        future = executor.schedule(
            scanner,
            args=[payload],
            timeout=task_seconds,
        )
        with _SCAN_EXECUTOR_LOCK:
            if _SCAN_SHUTDOWN or generation != _SCAN_GENERATION:
                future.cancel()  # type: ignore[no-untyped-call]
                raise _ScannerShutdown(_SCANNER_SHUT_DOWN)
            _SCAN_FUTURES.add(future)
    except (HttpError, asyncio.CancelledError):
        capacity.release()
        raise
    except _ScannerShutdown as exc:
        capacity.release()
        raise _scanner_shutdown(writer_id, kind) from exc
    except Exception as exc:
        capacity.release()
        raise scan_unavailable(
            f"{kind} safety scanner failed",
            error_kind="unexpected",
            writer_id=writer_id,
            kind=kind,
        ) from exc

    def release(done: Any) -> None:
        with _SCAN_EXECUTOR_LOCK:
            _SCAN_FUTURES.discard(done)
        capacity.release()

    future.add_done_callback(release)
    try:
        return await asyncio.wait_for(asyncio.wrap_future(future), timeout=wait_seconds)
    except TimeoutError as exc:
        future.cancel()  # type: ignore[no-untyped-call]
        if _scan_stopped(generation):
            raise _scanner_shutdown(writer_id, kind) from exc
        raise scan_unavailable(
            f"{kind} safety scan timed out", error_kind="timeout", writer_id=writer_id, kind=kind
        ) from exc
    except asyncio.CancelledError as exc:  # NOSONAR
        if _scan_stopped(generation):
            raise _scanner_shutdown(writer_id, kind) from exc
        raise
    except ProcessExpired as exc:
        raise scan_unavailable(
            f"{kind} safety scanner worker failed",
            error_kind="worker-crash",
            writer_id=writer_id,
            kind=kind,
        ) from exc
    except Exception as exc:
        if _scan_stopped(generation):
            raise _scanner_shutdown(writer_id, kind) from exc
        raise scan_unavailable(
            f"{kind} safety scanner failed",
            error_kind="unexpected",
            writer_id=writer_id,
            kind=kind,
        ) from exc


def _scan_request_payload(payload: bytes) -> SafetyResult:
    request = json.loads(payload)
    result = (
        scan_recall_body(request["body"])
        if request["operation"] == "recall"
        else scan_retain_body(request["body"])
    )
    if request["query"] is not None:
        result.extend(scan_query_values(request["query"]))
    return result


async def scan_request(
    body: dict[str, Any],
    *,
    operation: Literal["retain", "recall"],
    writer_id: str | None = None,
    query: list[tuple[str, str]] | None = None,
) -> SafetyResult:
    task_seconds = QUERY_SCAN_TASK_SECONDS if query else CORE_SCAN_TASK_SECONDS
    return await _scan_in_worker(
        {"body": body, "operation": operation, "query": query},
        kind="request",
        task_seconds=task_seconds,
        wait_seconds=task_seconds + 1.0,
        writer_id=writer_id,
    )


async def scan_facade_response(value: Any, *, writer_id: str | None = None) -> SafetyResult:
    return await _scan_in_worker(
        value,
        kind="response",
        task_seconds=FACADE_SCAN_TASK_SECONDS,
        wait_seconds=FACADE_SCAN_WAIT_SECONDS,
        writer_id=writer_id,
    )


def _scan_recalled_payload(payload: bytes) -> SafetyResult:
    return scan_recall_result(json.loads(payload))


async def scan_recalled(value: dict[str, Any], *, writer_id: str | None = None) -> SafetyResult:
    return await _scan_in_worker(
        value,
        kind="recall",
        task_seconds=CORE_SCAN_TASK_SECONDS,
        wait_seconds=CORE_SCAN_TASK_SECONDS + 1.0,
        writer_id=writer_id,
    )
