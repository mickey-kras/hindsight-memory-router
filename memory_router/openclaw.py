from __future__ import annotations

import asyncio
import json
import logging
import multiprocessing
from contextlib import suppress
from threading import BoundedSemaphore, Lock
from typing import Any
from urllib.parse import quote, urlencode

from pebble import ProcessExpired, ProcessPool

from .canonical import canonical_json, sha256_hex
from .errors import HttpError
from .facade_routes import FacadeRoute
from .hindsight import MAX_FACADE_RESPONSE_BYTES, HindsightGatewayError
from .logging import log_event
from .observability import current_request_id
from .openclaw_contracts import validate_facade_response, validate_openclaw_response
from .security import (
    SafetyResult,
    scan_facade_payload,
    scan_query_values,
    scan_recall_body,
    scan_retain_body,
)

logger = logging.getLogger(__name__)
FACADE_SCAN_WORKERS = 4
FACADE_SCAN_CAPACITY = 4
FACADE_SCAN_TASK_SECONDS = 30.0
FACADE_SCAN_WAIT_SECONDS = 31.0


class _FacadeScannerShutdown(RuntimeError):
    pass


_FACADE_SCANNER_SHUT_DOWN = "facade scanner shut down"
_RESPONSE_SCANNER_SHUT_DOWN = "response safety scanner is shut down"


def _new_facade_scan_executor() -> ProcessPool:
    return ProcessPool(
        max_workers=FACADE_SCAN_WORKERS,
        context=multiprocessing.get_context("spawn"),
    )


_FACADE_SCAN_EXECUTOR: ProcessPool | None = None
_FACADE_SCAN_EXECUTOR_LOCK = Lock()
_FACADE_SCAN_CAPACITY = BoundedSemaphore(value=FACADE_SCAN_CAPACITY)
_FACADE_SCAN_GENERATION = 0
_FACADE_SCAN_SHUTDOWN = False
_FACADE_SCAN_FUTURES: set[Any] = set()


def _scan_unavailable(message: str, *, error_kind: str, writer_id: str | None = None) -> HttpError:
    log_event(
        logger,
        "warning",
        "facade_scan_failed",
        request_id=current_request_id(),
        operation="facade_scan",
        error_kind=error_kind,
        outcome="failed",
        route_class="openclaw",
        writer_id=writer_id,
    )
    return HttpError(
        503,
        "facade_scan_unavailable",
        message,
        headers={"Retry-After": "1"},
    )


def _facade_scan_generation() -> int:
    with _FACADE_SCAN_EXECUTOR_LOCK:
        return _FACADE_SCAN_GENERATION


def _facade_scan_stopped(generation: int) -> bool:
    with _FACADE_SCAN_EXECUTOR_LOCK:
        return _FACADE_SCAN_SHUTDOWN or generation != _FACADE_SCAN_GENERATION


def _get_facade_scan_executor(expected_generation: int | None = None) -> ProcessPool:
    global _FACADE_SCAN_EXECUTOR
    stale = None
    with _FACADE_SCAN_EXECUTOR_LOCK:
        if _FACADE_SCAN_SHUTDOWN:
            raise _FacadeScannerShutdown(_FACADE_SCANNER_SHUT_DOWN)
        if expected_generation is not None and expected_generation != _FACADE_SCAN_GENERATION:
            raise _FacadeScannerShutdown(_FACADE_SCANNER_SHUT_DOWN)
        if _FACADE_SCAN_EXECUTOR is None or not _FACADE_SCAN_EXECUTOR.active:
            stale = _FACADE_SCAN_EXECUTOR
            _FACADE_SCAN_EXECUTOR = _new_facade_scan_executor()
        executor = _FACADE_SCAN_EXECUTOR
    if stale is not None:
        with suppress(Exception):
            stale.stop()  # type: ignore[no-untyped-call]
        with suppress(Exception):
            stale.join(timeout=5)
    return executor


async def _get_facade_scan_executor_async(expected_generation: int) -> ProcessPool:
    return await asyncio.to_thread(_get_facade_scan_executor, expected_generation)


def start_facade_scan_executor() -> None:
    global _FACADE_SCAN_CAPACITY, _FACADE_SCAN_SHUTDOWN
    with _FACADE_SCAN_EXECUTOR_LOCK:
        restarting = _FACADE_SCAN_SHUTDOWN
        _FACADE_SCAN_SHUTDOWN = False
        if restarting:
            _FACADE_SCAN_CAPACITY = BoundedSemaphore(value=FACADE_SCAN_CAPACITY)
            _FACADE_SCAN_FUTURES.clear()
    # Pebble starts workers lazily when ``active`` is first inspected. Do that
    # during startup so the first facade request never pays process-spawn cost.
    executor = _get_facade_scan_executor()
    if not executor.active:
        raise RuntimeError("facade scanner failed to start")


def _acquire_facade_scan_capacity() -> tuple[int, BoundedSemaphore] | None:
    with _FACADE_SCAN_EXECUTOR_LOCK:
        if _FACADE_SCAN_SHUTDOWN:
            raise _FacadeScannerShutdown(_FACADE_SCANNER_SHUT_DOWN)
        capacity = _FACADE_SCAN_CAPACITY
        if not capacity.acquire(blocking=False):
            return None
        return _FACADE_SCAN_GENERATION, capacity


def shutdown_facade_scan_executor() -> None:
    global _FACADE_SCAN_EXECUTOR, _FACADE_SCAN_GENERATION, _FACADE_SCAN_SHUTDOWN
    with _FACADE_SCAN_EXECUTOR_LOCK:
        _FACADE_SCAN_SHUTDOWN = True
        _FACADE_SCAN_GENERATION += 1
        executor = _FACADE_SCAN_EXECUTOR
        _FACADE_SCAN_EXECUTOR = None
        futures = tuple(_FACADE_SCAN_FUTURES)
    for future in futures:
        with suppress(Exception):
            future.cancel()
    if executor is not None:
        with suppress(Exception):
            executor.stop()  # type: ignore[no-untyped-call]
        with suppress(Exception):
            executor.join(timeout=5)


async def shutdown_facade_scan_executor_async() -> None:
    await asyncio.to_thread(shutdown_facade_scan_executor)


async def _scan_facade_response(value: Any, *, writer_id: str | None = None) -> SafetyResult:
    try:
        admission = _acquire_facade_scan_capacity()
    except _FacadeScannerShutdown as exc:
        raise _scan_unavailable(
            _RESPONSE_SCANNER_SHUT_DOWN,
            error_kind="shutdown",
            writer_id=writer_id,
        ) from exc
    if admission is None:
        raise _scan_unavailable(
            "response safety scanner is busy", error_kind="capacity", writer_id=writer_id
        )
    generation, capacity = admission
    try:
        payload = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(payload) > MAX_FACADE_RESPONSE_BYTES:
            raise _scan_unavailable(
                "response exceeded safety scan limits",
                error_kind="response-too-large",
                writer_id=writer_id,
            )
        executor = await _get_facade_scan_executor_async(generation)
        future = executor.schedule(
            scan_facade_payload,
            args=[payload],
            timeout=FACADE_SCAN_TASK_SECONDS,
        )
        with _FACADE_SCAN_EXECUTOR_LOCK:
            if _FACADE_SCAN_SHUTDOWN or generation != _FACADE_SCAN_GENERATION:
                future.cancel()  # type: ignore[no-untyped-call]
                raise _FacadeScannerShutdown(_FACADE_SCANNER_SHUT_DOWN)
            _FACADE_SCAN_FUTURES.add(future)
    except HttpError:
        capacity.release()
        raise
    except asyncio.CancelledError:
        capacity.release()
        raise
    except _FacadeScannerShutdown as exc:
        capacity.release()
        raise _scan_unavailable(
            _RESPONSE_SCANNER_SHUT_DOWN,
            error_kind="shutdown",
            writer_id=writer_id,
        ) from exc
    except Exception as exc:
        capacity.release()
        raise _scan_unavailable(
            "response safety scanner failed",
            error_kind="unexpected",
            writer_id=writer_id,
        ) from exc

    def release(done: Any) -> None:
        with _FACADE_SCAN_EXECUTOR_LOCK:
            _FACADE_SCAN_FUTURES.discard(done)
        capacity.release()

    future.add_done_callback(release)
    try:
        return await asyncio.wait_for(asyncio.wrap_future(future), timeout=FACADE_SCAN_WAIT_SECONDS)
    except TimeoutError as exc:
        future.cancel()  # type: ignore[no-untyped-call]
        if _facade_scan_stopped(generation):
            raise _scan_unavailable(
                _RESPONSE_SCANNER_SHUT_DOWN,
                error_kind="shutdown",
                writer_id=writer_id,
            ) from exc
        raise _scan_unavailable(
            "response safety scan timed out", error_kind="timeout", writer_id=writer_id
        ) from exc
    except asyncio.CancelledError as exc:
        if _facade_scan_stopped(generation):
            raise _scan_unavailable(
                _RESPONSE_SCANNER_SHUT_DOWN,
                error_kind="shutdown",
                writer_id=writer_id,
            ) from exc
        raise
    except ProcessExpired as exc:
        raise _scan_unavailable(
            "response safety scanner worker failed",
            error_kind="worker-crash",
            writer_id=writer_id,
        ) from exc
    except Exception as exc:
        if _facade_scan_stopped(generation):
            raise _scan_unavailable(
                _RESPONSE_SCANNER_SHUT_DOWN,
                error_kind="shutdown",
                writer_id=writer_id,
            ) from exc
        raise _scan_unavailable(
            "response safety scanner failed",
            error_kind="unexpected",
            writer_id=writer_id,
        ) from exc


class OpenClawFacade:
    """Policy-gated facade for the Hindsight endpoints used by the OpenClaw plugin."""

    def __init__(self, policy: Any) -> None:
        self.policy = policy

    async def forward(
        self,
        *,
        route: FacadeRoute,
        writer_id: str,
        params: dict[str, str],
        body: dict[str, Any] | None = None,
        query: list[tuple[str, str]] | None = None,
    ) -> Any:
        writer = self.policy.registry.writers.get(writer_id)
        if writer is None:
            await self._audit(
                writer_id,
                "openclaw_unknown_writer",
                {"method": route.method, "resource": route.resource},
                None,
            )
            raise HttpError(404, "unknown_writer", "writer is not registered")

        forwarded_query = [
            (key, value) for key, value in (query or []) if key in route.query_params
        ]
        supplied_query = {key for key, _ in forwarded_query}
        missing_query = [name for name in route.required_query_params if name not in supplied_query]
        if missing_query:
            raise HttpError(
                400,
                "invalid_request",
                f"missing required query parameter: {missing_query[0]}",
            )
        request_evidence: dict[str, Any] = {
            "bank_id": writer_id,
            "resource": route.resource,
            "query": [{"key": key, "value": value} for key, value in forwarded_query],
        }
        for name in route.params:
            request_evidence[name] = params[name]
        if body is not None:
            request_evidence["body"] = body

        if route.resource == "reflect" and body is not None:
            self.policy.limits.assert_recall_bounds(body)
        if route.template == "memories/dry-run-extract" and body is not None:
            if not isinstance(body.get("items"), list):
                raise HttpError(400, "invalid_request", "items must be an array")
            self.policy.limits.assert_retain_bounds(body)

        if route.read:
            await self.policy.limits.consume_recall(writer_id)
        else:
            await self.policy.limits.consume_retain(writer_id)

        # Route metadata and free-text query values are not persisted payload. Query
        # values decode valid Base64 but do not fail closed on ordinary URL syntax.
        scan_input = {
            key: value
            for key, value in request_evidence.items()
            if key not in {"resource", "query"}
        }
        scan = (
            scan_recall_body(scan_input)
            if route.request_scan == "recall"
            else scan_retain_body(scan_input)
        )
        scan.extend(scan_query_values(forwarded_query))
        if not scan.safe:
            await self._audit(writer_id, "openclaw_suspicious_request", request_evidence, scan)
            raise HttpError(422, "suspicious_content", "request blocked by memory-router policy")

        bank = quote(writer.write_bank, safe="")
        suffix = route.template
        for name in route.params:
            suffix = suffix.replace("{" + name + "}", quote(params[name], safe=""))
        path = f"/v1/default/banks/{bank}"
        if suffix:
            path += f"/{suffix}"
        if forwarded_query:
            path += "?" + urlencode(forwarded_query)

        value = await self.policy.hindsight.openclaw_request(
            f"openclaw_{route.operation}",
            route.method,
            path,
            body,
            expected_status=route.success_status,
            allow_empty_response=route.allow_empty_response,
        )
        if value is not None:
            response_scan = await _scan_facade_response(value, writer_id=writer_id)
            if response_scan.findings and all(
                finding.matched in {"facade_field_limit", "facade_time_limit"}
                for finding in response_scan.findings
            ):
                error_kind = (
                    "timeout"
                    if any(
                        finding.matched == "facade_time_limit" for finding in response_scan.findings
                    )
                    else "response-too-large"
                )
                raise _scan_unavailable(
                    "response exceeded safety scan limits",
                    error_kind=error_kind,
                    writer_id=writer_id,
                )
            if not response_scan.safe:
                await self._audit(
                    writer_id,
                    "openclaw_suspicious_provider_response",
                    {"resource": route.resource, "response": value},
                    response_scan,
                )
                raise HttpError(
                    502,
                    "hindsight_unsafe_response",
                    "upstream memory service returned unsafe content",
                )
        try:
            if route.strict_contract:
                validate_openclaw_response(
                    route.method, route.resource, params.get("mental_model_id"), value
                )
            else:
                validate_facade_response(
                    value, route.response, allow_empty=route.allow_empty_response
                )
        except ValueError as exc:
            raise HindsightGatewayError(
                "invalid-response", operation=f"openclaw_{route.operation}", method=route.method
            ) from exc
        return value

    async def _audit(
        self,
        writer_id: str,
        reason: str,
        value: Any,
        scan: SafetyResult | None,
    ) -> None:
        try:
            digest = sha256_hex(canonical_json(value))
        except (ValueError, RecursionError):
            digest = sha256_hex(repr(type(value)))
        findings = [] if scan is None else [finding.public() for finding in scan.findings]
        try:
            await self.policy._quarantine(  # noqa: SLF001 - same package policy boundary
                {
                    "writerId": writer_id,
                    "source": "openclaw",
                    "kind": "security_event",
                    "reason": reason,
                    "dedupeKey": f"{reason}:{writer_id}:{digest}",
                    "payload": {
                        "action": reason,
                        "content_sha256": digest,
                        "findings": findings,
                    },
                }
            )
        except Exception as exc:
            # Blocking is independent from audit availability; never log raw payload/content.
            log_event(
                logger,
                "error",
                "openclaw_security_audit_failed",
                error=exc,
                request_id=current_request_id(),
                operation="security_audit",
                error_kind="unexpected",
                outcome="failed",
                route_class="openclaw",
                writer_id=writer_id,
                reason=reason,
            )
