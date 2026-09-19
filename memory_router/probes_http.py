from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from . import probes
from .auth import AuthFailureAuditor, router_authorized
from .hindsight import HindsightGateway, HindsightGatewayError, hindsight_log_fields
from .logging import log_event
from .principal_gate import authenticate_principal, principal_token_present
from .principals import PrincipalResolver
from .repository import QuarantineRepository

logger = logging.getLogger(__name__)
_REFRESH_TIMEOUT_SECONDS = 15.0
_DEPENDENCY_PROBE_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class ProbesDeps:
    repository: QuarantineRepository | None
    hindsight: HindsightGateway | None
    router_token: str | None
    allow_anonymous: bool
    resolver: PrincipalResolver | None
    auditor: AuthFailureAuditor | None
    auth_failure_rate: Callable[[str], Awaitable[None]]


def _require_component[T](value: T | None, component: str) -> T:
    if value is None:
        raise RuntimeError(f"memory-router runtime {component} is not initialized")
    return value


async def _database_health(repository: QuarantineRepository) -> probes.ProbeResult[None]:
    async def ping() -> None:
        async with asyncio.timeout(_DEPENDENCY_PROBE_TIMEOUT_SECONDS):
            await repository.ping()

    return await probes.timed_probe(ping, probes.storage_readiness_log_state)


async def _hindsight_health(hindsight: HindsightGateway) -> probes.ProbeResult[dict[str, object]]:
    async def health() -> dict[str, object]:
        async with asyncio.timeout(_DEPENDENCY_PROBE_TIMEOUT_SECONDS):
            return await hindsight.health()

    return await probes.timed_probe(health, probes.readiness_log_state)


async def readiness_response(deps: ProbesDeps) -> Response:
    async def refresh() -> Response:
        status_code = 200
        payload: Any
        try:
            repository = _require_component(deps.repository, "repository")
            hindsight = _require_component(deps.hindsight, "Hindsight gateway")
            database_check, hindsight_check = await asyncio.wait_for(
                asyncio.gather(_database_health(repository), _hindsight_health(hindsight)),
                timeout=_REFRESH_TIMEOUT_SECONDS,
            )
            if not database_check.healthy or not hindsight_check.healthy:
                status_code, payload = 503, {"status": "unhealthy"}
            else:
                payload = hindsight_check.value
        except Exception:
            status_code, payload = 503, {"status": "unhealthy"}
        return JSONResponse(payload, status_code=status_code)

    return await probes.readiness.get(refresh)


async def _full_readiness_authorized(request: Request, deps: ProbesDeps) -> bool:
    authorization = request.headers.get("authorization")
    if router_authorized(authorization, deps.router_token, deps.allow_anonymous):
        return True
    if deps.resolver is None or not principal_token_present(authorization):
        return False
    principal = await authenticate_principal(
        request,
        resolver=deps.resolver,
        auditor=_require_component(deps.auditor, "auth auditor"),
        route_class="readiness",
        on_failure=lambda: deps.auth_failure_rate("router"),
    )
    return principal is not None


async def readiness_probe_response(request: Request, deps: ProbesDeps) -> Response:
    response = await readiness_response(deps)
    if await _full_readiness_authorized(request, deps):
        return response
    status = "healthy" if response.status_code == 200 else "unhealthy"
    return JSONResponse({"status": status}, status_code=response.status_code)


async def version_response(hindsight: HindsightGateway | None) -> Response:
    async def refresh() -> Response:
        try:
            gateway = _require_component(hindsight, "Hindsight gateway")
            payload = await asyncio.wait_for(gateway.version(), timeout=_REFRESH_TIMEOUT_SECONDS)
        except TimeoutError as exc:
            error = HindsightGatewayError("timeout", operation="version", method="GET")
            error.__cause__ = exc
            return version_failure(error)
        except HindsightGatewayError as exc:
            return version_failure(exc)
        except Exception as exc:
            error = HindsightGatewayError(
                "network", operation="version", method="GET", client_status=503
            )
            error.__cause__ = exc
            return version_failure(error)
        return JSONResponse(payload)

    return await probes.version.get(refresh)


def version_failure(error: HindsightGatewayError) -> Response:
    log_event(
        logger,
        "warning",
        "hindsight_request_failed",
        **hindsight_log_fields(error),
        error=error,
        outcome="failed",
        route_class="version",
    )
    return JSONResponse(error.body(), status_code=error.status, headers=error.headers)
