from __future__ import annotations

import hashlib
import hmac
import sys
import time
from typing import Any


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


class AuthFailureAuditor:
    def __init__(self, store: Any) -> None:
        self.store = store
        self.last: dict[str, int] = {}

    async def record(self, route_group: str) -> None:
        now = int(time.time() * 1000)
        event_key = f"event:{route_group}"
        if now - self.last.get(event_key, 0) >= 60_000:
            self.last[event_key] = now
            sys.stderr.write(f'{{"event":"auth_failed","route_group":"{route_group}"}}\n')
        try:
            from datetime import datetime, timezone
            at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            await self.store.put({
                "timestamp":at,"kind":"security_event","reason":"auth_failed","source":"http",
                "dedupeKey":f"auth_failed:{route_group}","payload":{"action":"auth_failed","route_group":route_group},
            })
        except Exception as exc:
            error_key = f"error:{route_group}"
            if now - self.last.get(error_key, 0) >= 60_000:
                self.last[error_key] = now
                sys.stderr.write(f"memory-router could not record an auth_failed security event: {type(exc).__name__}\n")
