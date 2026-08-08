from __future__ import annotations

import hashlib
import hmac
import sys
import time
from typing import Any, Mapping

from .quarantine.store import EncryptedDatabaseQuarantineStore, QuarantineInput


def bearer_matches(authorization: str | None, tokens: list[str]) -> bool:
    if not authorization or not tokens:
        return False
    presented = hashlib.sha256(authorization.encode()).digest()
    matched = False
    for token in tokens:
        expected = hashlib.sha256(f"Bearer {token}".encode()).digest()
        matched = hmac.compare_digest(presented, expected) or matched
    return matched


def is_router_authorized(
    authorization: str | None, router_token: str | None, allow_anonymous: bool
) -> bool:
    return bearer_matches(authorization, [router_token]) if router_token else allow_anonymous


def is_admin_authorized(
    authorization: str | None,
    scope: str,
    *,
    legacy: str | None,
    read: str | None,
    review: str | None,
    cleanup: str | None,
) -> bool:
    tokens = [legacy]
    if scope == "read":
        tokens.extend([read, review])
    elif scope == "review":
        tokens.append(review)
    elif scope == "cleanup":
        tokens.append(cleanup)
    return bearer_matches(authorization, [token for token in tokens if token])


class AuthFailureAuditor:
    def __init__(self, store: EncryptedDatabaseQuarantineStore) -> None:
        self.store = store
        self._last: dict[str, float] = {}

    def _log(self, channel: str, group: str, line: str) -> None:
        key = f"{channel}:{group}"
        now = time.monotonic()
        if now - self._last.get(key, -1e9) < 60:
            return
        self._last[key] = now
        sys.stderr.write(line)

    async def __call__(self, route_group: str) -> None:
        self._log(
            "event",
            route_group,
            f'{{"event":"auth_failed","route_group":"{route_group}"}}\n',
        )
        try:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z")
            await self.store.put(
                QuarantineInput(
                    timestamp=timestamp,
                    kind="security_event",
                    reason="auth_failed",
                    source="http",
                    dedupe_key=f"auth_failed:{route_group}",
                    payload={"action": "auth_failed", "route_group": route_group},
                )
            )
        except BaseException as exc:
            self._log(
                "error",
                route_group,
                "memory-router could not record an auth_failed security event: "
                f"{type(exc).__name__}\n",
            )
