from __future__ import annotations

import re
from urllib.parse import unquote

from fastapi import Request

from .errors import HttpError
from .request_dispatch import MEMORY_ROUTE

_PERCENT_DOT = re.compile(r"%2e", re.I)
_INVALID_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MAX_PATH_PROBE_DECODES = 8


def _route_class(request: Request) -> str:
    path = _raw_pathname(request)
    if path in {"/health", "/health/ready", "/ready"}:
        return "readiness"
    if path == "/health/live":
        return "liveness"
    if path == "/version":
        return "version"
    if path == "/metrics":
        return "metrics"
    if path.startswith("/admin/"):
        return "admin"
    if MEMORY_ROUTE.fullmatch(path):
        return "memory"
    if path.startswith("/v1/default/banks/"):
        return "openclaw"
    return "unmatched"


def _raw_pathname(request: Request) -> str:
    raw = request.scope.get("raw_path")
    path = raw.decode("latin-1") if isinstance(raw, bytes) else request.url.path
    return _normalize_dot_segments(path)


def _normalize_dot_segments(path: str) -> str:
    segments = path.split("/")
    output: list[str] = []
    last_index = len(segments) - 1
    for index, segment in enumerate(segments):
        dot_segment = _PERCENT_DOT.sub(".", segment)
        if dot_segment in {".", ".."}:
            _apply_dot_segment(output, dot_segment, index == last_index)
            continue
        output.append(segment)
    return "/".join(output)


def _apply_dot_segment(output: list[str], segment: str, trailing: bool) -> None:
    if segment == ".." and output and output != [""]:
        output.pop()
    if trailing:
        output.append("")


def _decode_path_segment(value: str) -> str:
    if _INVALID_PERCENT.search(value):
        raise HttpError(
            400, "invalid_path_encoding", "path segment contains malformed percent-encoding"
        )
    try:
        decoded = unquote(value, encoding="utf-8", errors="strict")
    except ValueError as exc:
        raise HttpError(
            400, "invalid_path_encoding", "path segment contains malformed percent-encoding"
        ) from exc
    probe = decoded
    for _ in range(_MAX_PATH_PROBE_DECODES):
        if "/" in probe:
            raise HttpError(400, "invalid_path_segment", "encoded path separators are not allowed")
        if probe in {".", ".."}:
            raise HttpError(400, "invalid_path_segment", "dot path segments are not allowed")
        try:
            next_probe = unquote(probe, encoding="utf-8", errors="strict")
        except ValueError:
            break
        if next_probe == probe:
            break
        probe = next_probe
    else:
        if probe in {".", ".."}:
            raise HttpError(400, "invalid_path_segment", "dot path segments are not allowed")
        raise HttpError(400, "invalid_path_encoding", "path segment has excessive nested encoding")
    return decoded
