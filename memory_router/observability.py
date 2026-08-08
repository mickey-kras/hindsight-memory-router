from __future__ import annotations

import re
import secrets
from collections.abc import Awaitable, Callable
from contextvars import ContextVar, Token
from typing import Any

_REQUEST_ID = ContextVar[str | None]("memory_router_request_id", default=None)
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEADER = b"x-request-id"


def current_request_id() -> str | None:
    return _REQUEST_ID.get()


def _resolve_request_id(scope: dict[str, Any]) -> str:
    for name, value in scope.get("headers", []):
        if name.lower() != _HEADER:
            continue
        try:
            candidate = value.decode("ascii")
        except UnicodeDecodeError:
            break
        if _REQUEST_ID_RE.fullmatch(candidate):
            return candidate
        break
    return secrets.token_hex(16)


class RequestIdMiddleware:
    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request_id = _resolve_request_id(scope)
        token: Token[str | None] = _REQUEST_ID.set(request_id)

        async def send_with_request_id(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((_HEADER, request_id.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            _REQUEST_ID.reset(token)
