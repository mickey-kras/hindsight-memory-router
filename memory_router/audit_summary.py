from __future__ import annotations

import re
from typing import Any

from .canonical import sha256_hex
from .facade_routes import FACADE_ROUTES

_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
)
_RESOURCES = frozenset(route.resource for route in FACADE_ROUTES)
_STATIC_ROUTES = frozenset(
    {
        "/health",
        "/health/live",
        "/health/ready",
        "/ready",
        "/version",
        "/metrics",
        "/v1/default/banks",
    }
)


def normalized_method(value: object) -> str:
    method = value.upper() if isinstance(value, str) else ""
    return method if method in _METHODS else "OTHER"


def normalized_route(value: object) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        return "/unmatched"
    path = value.split("?", 1)[0].split("#", 1)[0]
    if path in _STATIC_ROUTES:
        return path
    for route in FACADE_ROUTES:
        if route.pattern.fullmatch(path):
            suffix = f"/{route.template}" if route.template else ""
            return f"/v1/default/banks/{{bank_id}}{suffix}"
    if path.startswith("/admin/"):
        return "/admin/{unmatched}"
    if path.startswith("/v1/default/banks/"):
        return "/v1/default/banks/{bank_id}/{unmatched}"
    return "/unmatched"


def security_audit_summary(item: dict[str, Any]) -> str | None:
    if item.get("kind") != "security_event":
        return None
    payload = item.get("payload")
    if not isinstance(payload, dict):
        return None
    reason = item.get("reason")
    if reason == "auth_failed":
        group = payload.get("route_group")
        return f"Authentication failed: {group if group in ('router', 'admin') else 'unmatched'}"
    if reason == "denied_endpoint":
        return f"Denied: {normalized_method(payload.get('method'))} {normalized_route(payload.get('path'))}"
    if reason == "openclaw_unknown_writer":
        writer = item.get("writerId")
        if not isinstance(writer, str):
            label = "unknown"
        elif re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", writer):
            label = writer
        else:
            label = f"sha256:{sha256_hex(writer)[:16]}"
        resource = payload.get("resource")
        resource = resource if isinstance(resource, str) and resource in _RESOURCES else "unmatched"
        return f"Unknown writer: {label}; {normalized_method(payload.get('method'))} {resource or 'bank'}"
    return None
