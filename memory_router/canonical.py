from __future__ import annotations

import hashlib
import math
from typing import Any

import rfc8785

_MAX_SAFE_INTEGER = (1 << 53) - 1


def canonical_json(value: Any) -> str:
    try:
        return rfc8785.dumps(_rfc8785_safe(value)).decode("utf-8")
    except (
        rfc8785.CanonicalizationError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
    ) as exc:
        raise ValueError("value must contain JSON values only") from exc


def _rfc8785_safe(value: Any) -> Any:
    match value:
        case None | bool():
            return value
        case str():
            value.encode("utf-8", errors="strict")
            return value
        case int():
            if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
                raise ValueError("non-finite JSON number")
            return value
        case float():
            if not math.isfinite(value):
                raise ValueError("non-finite JSON number")
            return value
        case list():
            return [_rfc8785_safe(entry) for entry in value]
        case dict():
            if any(not isinstance(key, str) for key in value):
                raise ValueError("value must contain JSON values only")
            return {key: _rfc8785_safe(entry) for key, entry in value.items()}
        case _:
            raise ValueError("value must contain JSON values only")


def assert_json_depth(value: Any, *, max_depth: int) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ValueError("JSON nesting depth exceeds limit")
        if isinstance(current, dict):
            stack.extend((entry, depth + 1) for entry in current.values())
        elif isinstance(current, list):
            stack.extend((entry, depth + 1) for entry in current)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
