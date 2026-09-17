"""Authorization gate for principal mode: decision auditing, authentication, grant checks."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from .auth import AuthFailureAuditor
from .errors import HttpError
from .logging import log_event
from .observability import current_request_id
from .principals import (
    CLAIMED_AGENT_HEADER,
    SCOPE_QUARANTINE_REVIEW,
    TOKEN_PREFIX,
    PrincipalResolver,
    PrincipalSession,
)

logger = logging.getLogger(__name__)

_PRINCIPAL_FAILURE_REASONS = {
    "invalid-format": "invalid-token-format",
    "unknown-key": "unknown-key-id",
    "wrong-secret": "wrong-secret",
    "expired": "expired-token",
    "revoked": "revoked-token",
}


def log_authorization_decision(
    *,
    route_class: str,
    session: PrincipalSession,
    bank: str,
    scope: str,
    allowed: bool,
    latency_ms: float,
) -> None:
    log_event(
        logger,
        "info" if allowed else "warning",
        "authorization_decision",
        request_id=current_request_id(),
        operation=scope,
        principal=session.principal_id,
        token_key_id=session.key_id,
        bank=bank,
        scope=scope,
        decision="allow" if allowed else "deny",
        status=200 if allowed else 403,
        latency_ms=latency_ms,
        source="http",
        outcome="healthy" if allowed else "failed",
        route_class=route_class,
    )


async def authenticate_principal(
    request: Request,
    *,
    resolver: PrincipalResolver,
    auditor: AuthFailureAuditor,
    route_class: str,
    on_failure: Callable[[], Awaitable[None]],
) -> PrincipalSession | None:
    result = resolver.authenticate(request.headers.get("authorization"))
    if result.status == "ok" and result.session is not None:
        session = result.session
        claimed = request.headers.get(CLAIMED_AGENT_HEADER)
        if claimed is not None and claimed != session.principal_id:
            auditor.log_failure(route_class, reason="agent-claim-mismatch")
            await on_failure()
            await auditor.persist("router", route_class)
            raise HttpError(
                403,
                "agent_claim_mismatch",
                "claimed agent does not match the authenticated principal",
            )
        return session
    auditor.log_failure(route_class, reason=_PRINCIPAL_FAILURE_REASONS[result.status])
    await on_failure()
    await auditor.persist("router", route_class)
    return None


def require_grant(
    *,
    session: PrincipalSession,
    scope: str,
    bank: str,
    route_class: str,
) -> None:
    started = time.monotonic()
    allowed = PrincipalResolver.authorize(session, scope, bank)
    latency_ms = round((time.monotonic() - started) * 1000, 3)
    log_authorization_decision(
        route_class=route_class,
        session=session,
        bank=bank,
        scope=scope,
        allowed=allowed,
        latency_ms=latency_ms,
    )
    if not allowed:
        raise HttpError(403, "authorization_denied", "principal lacks the required grant")


_AUTHENTICATION_REQUIRED = {
    "error": "unauthorized",
    "message": "authentication required",
}
_PRINCIPAL_ADMIN_METADATA_PATHS = frozenset({"/admin/quarantine/queue", "/admin/quarantine/stats"})


def principal_token_present(authorization: str | None) -> bool:
    return authorization is not None and authorization.startswith(f"Bearer {TOKEN_PREFIX}")


@dataclass(frozen=True, slots=True)
class PrincipalAdminDeps:
    resolver: PrincipalResolver
    auditor: AuthFailureAuditor
    admin: Any
    on_auth_failure: Callable[[], Awaitable[None]]
    principal_rate: Callable[[PrincipalSession, str, str], Awaitable[None]]
    queue_response: Callable[[Request, Any, tuple[str, ...]], Awaitable[Response]]


async def principal_admin_metadata_response(
    request: Request,
    pathname: str,
    method: str,
    deps: PrincipalAdminDeps,
) -> Response:
    route_class = "admin"
    principal = await authenticate_principal(
        request,
        resolver=deps.resolver,
        auditor=deps.auditor,
        route_class=route_class,
        on_failure=deps.on_auth_failure,
    )
    if principal is None:
        return JSONResponse(_AUTHENTICATION_REQUIRED, status_code=401)
    if method != "GET" or pathname not in _PRINCIPAL_ADMIN_METADATA_PATHS:
        return JSONResponse(_AUTHENTICATION_REQUIRED, status_code=401)
    banks = PrincipalResolver.quarantine_review_banks(principal)
    bank_id = request.query_params.get("bank_id")
    scoped: tuple[str, ...]
    if bank_id is not None:
        require_grant(
            session=principal,
            scope=SCOPE_QUARANTINE_REVIEW,
            bank=bank_id,
            route_class=route_class,
        )
        scoped = (bank_id,)
    else:
        if not banks:
            require_grant(
                session=principal,
                scope=SCOPE_QUARANTINE_REVIEW,
                bank="-",
                route_class=route_class,
            )
        scoped = tuple(banks)
    await deps.principal_rate(principal, SCOPE_QUARANTINE_REVIEW, route_class)
    if pathname == "/admin/quarantine/stats":
        return JSONResponse(await deps.admin.bank_stats(scoped))
    return await deps.queue_response(request, deps.admin, scoped)
