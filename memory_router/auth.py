from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any

from .logging import log_event
from .observability import current_request_id
from .timestamps import iso_now

logger = logging.getLogger(__name__)


def bearer_matches(authorization: str | None, token: str | None) -> bool:
    if not authorization or not token:
        return False
    presented = hashlib.sha256(authorization.encode()).digest()
    expected = hashlib.sha256(f"Bearer {token}".encode()).digest()
    return hmac.compare_digest(presented, expected)


def router_authorized(authorization: str | None, token: str | None, allow_anonymous: bool) -> bool:
    return bearer_matches(authorization, token) if token else allow_anonymous


def admin_authorized(authorization: str | None, scope: str, tokens: dict[str, str | None]) -> bool:
    allowed: list[str] = []
    if tokens.get("legacy"):
        allowed.append(tokens["legacy"] or "")
    if scope == "read":
        allowed.extend(value for value in (tokens.get("read"), tokens.get("review")) if value)
    elif scope == "review" and tokens.get("review"):
        allowed.append(tokens["review"] or "")
    elif scope == "cleanup" and tokens.get("cleanup"):
        allowed.append(tokens["cleanup"] or "")
    return any(bearer_matches(authorization, token) for token in allowed)


def admin_token_recognized(authorization: str | None, tokens: dict[str, str | None]) -> bool:
    return any(bearer_matches(authorization, token) for token in tokens.values() if token)


class AuthFailureAuditor:
    def __init__(self, store: Any) -> None:
        self.store = store

    def log_failure(self, route_class: str | None = None, *, reason: str | None = None) -> None:
        log_event(
            logger,
            "warning",
            "authentication_failed",
            request_id=current_request_id(),
            operation="authenticate",
            error_kind="invalid-credentials",
            http_status=401,
            outcome="failed",
            route_class=route_class or "unmatched",
            reason=reason,
        )

    async def persist(self, route_group: str, route_class: str | None = None) -> None:
        try:
            await self.store.put(
                {
                    "timestamp": iso_now(),
                    "kind": "security_event",
                    "reason": "auth_failed",
                    "source": "http",
                    "dedupeKey": f"auth_failed:{route_group}",
                    "payload": {"action": "auth_failed", "route_group": route_group},
                }
            )
        except Exception as exc:
            log_event(
                logger,
                "error",
                "authentication_audit_failed",
                error=exc,
                request_id=current_request_id(),
                operation="security_audit",
                error_kind="unexpected",
                outcome="failed",
                route_class=route_class or "unmatched",
            )
