"""Authorization gate for principal mode: denial logging, authentication, grant checks."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import Request

from .auth import AuthFailureAuditor
from .errors import HttpError
from .logging import log_event
from .observability import current_request_id
from .principals import CLAIMED_AGENT_HEADER, PrincipalResolver, PrincipalSession

logger = logging.getLogger(__name__)


def log_authorization_denied(
    *, route_class: str, session: PrincipalSession, scope: str | None, reason: str
) -> None:
    log_event(
        logger,
        "warning",
        "authorization_denied",
        request_id=current_request_id(),
        operation="authenticate",
        http_status=403,
        outcome="failed",
        route_class=route_class,
        principal=session.principal_id,
        key_id=session.key_id,
        scope=scope,
        reason=reason,
    )


async def authenticate_principal(
    request: Request,
    *,
    resolver: PrincipalResolver,
    auditor: AuthFailureAuditor,
    route_class: str,
    on_failure: Callable[[], Awaitable[None]],
) -> PrincipalSession | None:
    session = resolver.authenticate(request.headers.get("authorization"))
    if session is not None:
        claimed = request.headers.get(CLAIMED_AGENT_HEADER)
        if claimed is not None and claimed != session.principal_id:
            log_authorization_denied(
                route_class=route_class,
                session=session,
                scope=None,
                reason="agent-claim-mismatch",
            )
            raise HttpError(
                403,
                "agent_claim_mismatch",
                "claimed agent does not match the authenticated principal",
            )
        return session
    auditor.log_failure(route_class)
    await on_failure()
    await auditor.persist("router", route_class)
    return None


def require_grant(
    *,
    resolver: PrincipalResolver,
    session: PrincipalSession,
    scope: str,
    bank: str,
    route_class: str,
) -> None:
    if resolver.authorize(session, scope, bank):
        return
    log_authorization_denied(
        route_class=route_class,
        session=session,
        scope=scope,
        reason="scope-not-granted",
    )
    raise HttpError(403, "authorization_denied", "principal lacks the required grant")
