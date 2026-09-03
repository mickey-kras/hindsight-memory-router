from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi.responses import JSONResponse, Response

from .hindsight import HindsightGatewayError
from .logging import log_event

logger = logging.getLogger(__name__)

_READINESS_FAILURE_LOG_INTERVAL_SECONDS = 60.0


class _ReadinessLogState:
    def __init__(
        self,
        failure_event: str = "hindsight_readiness_failed",
        recovery_event: str = "hindsight_readiness_recovered",
        operation: str = "health",
    ) -> None:
        self.failure_event = failure_event
        self.recovery_event = recovery_event
        self.operation = operation
        self.healthy: bool | None = None
        self.last_failure_log: dict[str, float] = {}
        self.candidate: bool | None = None
        self.consecutive = 0

    def record(self, error: Exception | None, duration_ms: float) -> None:
        now = time.monotonic()
        next_healthy = error is None
        if self.candidate == next_healthy:
            self.consecutive += 1
        else:
            self.candidate = next_healthy
            self.consecutive = 1
        if self.consecutive < 2:
            return
        if error is None:
            if self.healthy is False:
                log_event(
                    logger,
                    "info",
                    self.recovery_event,
                    operation=self.operation,
                    upstream_method="GET" if self.operation == "health" else None,
                    outcome="healthy",
                    operation_duration_ms=duration_ms,
                    route_class="readiness",
                )
            self.healthy = True
            return

        error_kind = (
            error.kind
            if isinstance(error, HindsightGatewayError)
            else "timeout"
            if isinstance(error, TimeoutError)
            else "storage"
            if self.operation == "storage_health"
            else "unexpected"
        )
        last_failure_log = self.last_failure_log.get(error_kind)
        if (
            self.healthy is not False
            or last_failure_log is None
            or now - last_failure_log >= _READINESS_FAILURE_LOG_INTERVAL_SECONDS
        ):
            fields: dict[str, Any] = {
                "operation": self.operation,
                "upstream_method": "GET" if self.operation == "health" else None,
                "error_kind": error_kind,
                "outcome": "unhealthy",
                "operation_duration_ms": duration_ms,
                "route_class": "readiness",
            }
            if isinstance(error, HindsightGatewayError):
                fields["upstream_status"] = error.upstream_status
            log_event(logger, "warning", self.failure_event, error=error, **fields)
            self.last_failure_log[error_kind] = now
        self.healthy = False


_readiness_log_state = _ReadinessLogState()
_storage_readiness_log_state = _ReadinessLogState(
    "storage_readiness_failed", "storage_readiness_recovered", "storage_health"
)
_READINESS_CACHE_SECONDS = 1.0
_CACHE_MAX_STALENESS_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class _CachedProbe:
    created_at: float
    status_code: int
    body: bytes


class _ProbeCache:
    def __init__(self, fallback: dict[str, Any]) -> None:
        self.cache: _CachedProbe | None = None
        self.lock: asyncio.Lock | None = None
        self.fallback = fallback

    async def get(self, refresh: Callable[[], Awaitable[Response]]) -> Response:
        now = time.monotonic()
        if self.cache is not None and now - self.cache.created_at < _READINESS_CACHE_SECONDS:
            return _cached_probe_response(self.cache)
        if self.lock is None:
            self.lock = asyncio.Lock()
        if self.lock.locked():
            if (
                self.cache is not None
                and now - self.cache.created_at <= _CACHE_MAX_STALENESS_SECONDS
            ):
                return _cached_probe_response(self.cache)
            return JSONResponse(self.fallback, status_code=503)
        async with self.lock:
            now = time.monotonic()
            if self.cache is not None and now - self.cache.created_at < _READINESS_CACHE_SECONDS:
                return _cached_probe_response(self.cache)
            response = await refresh()
            self.cache = _CachedProbe(time.monotonic(), response.status_code, bytes(response.body))
            return response


_readiness = _ProbeCache(fallback={"status": "unhealthy"})
_version = _ProbeCache(
    fallback={
        "error": "hindsight_unavailable",
        "message": "Upstream memory service is unavailable",
    }
)


def _cached_probe_response(cached: _CachedProbe) -> Response:
    return Response(
        content=cached.body, status_code=cached.status_code, media_type="application/json"
    )
