from __future__ import annotations

import json

from fastapi import Request


def request(
    method: str,
    path: str,
    *,
    body: object | bytes | None = None,
    headers: dict[str, str] | None = None,
    query: str = "",
) -> Request:
    if isinstance(body, bytes):
        raw = body
    elif body is None:
        raw = b""
    else:
        raw = json.dumps(body).encode()
    header_values = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "headers": header_values,
        "query_string": query.encode(),
    }
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return Request(scope, receive)
