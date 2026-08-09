from __future__ import annotations

import re
import secrets
from contextvars import ContextVar, Token

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_REQUEST_ID = ContextVar[str | None]("memory_router_request_id", default=None)
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEADER = b"x-request-id"


def current_request_id() -> str | None:
    return _REQUEST_ID.get()


def _resolve_request_id(scope: Scope) -> str:
    candidate = Headers(scope=scope).get("x-request-id")
    if candidate is not None and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return secrets.token_hex(16)


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request_id = _resolve_request_id(scope)
        token: Token[str | None] = _REQUEST_ID.set(request_id)

        async def send_with_request_id(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((_HEADER, request_id.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            _REQUEST_ID.reset(token)
