from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from . import metrics
from .auth import AuthFailureAuditor, admin_authorized
from .principal_gate import authenticate_principal, principal_token_present, require_grant
from .principals import SCOPE_QUARANTINE_REVIEW, PrincipalResolver, PrincipalSession
from .repository import QuarantineRepository
from .timestamps import iso_now

_AUTHENTICATION_REQUIRED = {
    "error": "unauthorized",
    "message": "authentication required",
}


@dataclass(frozen=True, slots=True)
class MetricsDeps:
    admin_tokens: dict[str, str | None]
    resolver: PrincipalResolver | None
    auditor: AuthFailureAuditor
    repository: QuarantineRepository
    admin_auth: Callable[[Request, str], Awaitable[bool]]
    admin_rate: Callable[[str], Awaitable[None]]
    principal_rate: Callable[[PrincipalSession, str, str], Awaitable[None]]
    auth_failure_rate: Callable[[str], Awaitable[None]]


def metrics_route_enabled(pathname: str, method: str, enabled: bool) -> bool:
    return pathname == "/metrics" and method == "GET" and enabled


async def metrics_endpoint_response(request: Request, deps: MetricsDeps) -> Response:
    authorization = request.headers.get("authorization")
    if not admin_authorized(authorization, "read", deps.admin_tokens):
        if deps.resolver is not None and principal_token_present(authorization):
            return await _principal_metrics_response(request, deps)
        if not await deps.admin_auth(request, "read"):
            return JSONResponse(_AUTHENTICATION_REQUIRED, status_code=401)
    await deps.admin_rate("GET")
    return await _metrics_response(deps.repository)


async def _principal_metrics_response(request: Request, deps: MetricsDeps) -> Response:
    resolver = deps.resolver
    if resolver is None:
        raise RuntimeError("memory-router runtime principal resolver is not initialized")
    principal = await authenticate_principal(
        request,
        resolver=resolver,
        auditor=deps.auditor,
        route_class="metrics",
        on_failure=lambda: deps.auth_failure_rate("admin"),
    )
    if principal is None:
        return JSONResponse(_AUTHENTICATION_REQUIRED, status_code=401)
    if not PrincipalResolver.quarantine_review_banks(principal):
        require_grant(
            session=principal,
            scope=SCOPE_QUARANTINE_REVIEW,
            bank="-",
            route_class="metrics",
        )
    await deps.principal_rate(principal, SCOPE_QUARANTINE_REVIEW, "metrics")
    return await _metrics_response(deps.repository)


async def _metrics_response(repository: QuarantineRepository) -> Response:
    stats = await repository.stats(iso_now())
    metrics.set_review_side_effect_started(stats["review_side_effect_started_items"])
    return Response(metrics.render(), media_type=metrics.CONTENT_TYPE)
