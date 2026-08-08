from __future__ import annotations

import hashlib
import math
from typing import Any

import rfc8785

_MAX_SAFE_INTEGER = (1 << 53) - 1


def canonical_json(value: Any) -> str:
    try:
        return rfc8785.dumps(_rfc8785_safe(value)).decode("utf-8")
    except (rfc8785.CanonicalizationError, UnicodeError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("value must contain JSON values only") from exc


def _rfc8785_safe(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace").decode("utf-8")
    if isinstance(value, int):
        if -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            return value
        try:
            converted = float(value)
        except OverflowError:
            return str(value)
        return converted if math.isfinite(converted) else str(value)
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return str(value)
    if isinstance(value, list):
        return [_rfc8785_safe(entry) for entry in value]
    if isinstance(value, dict):
        return {
            str(key).encode("utf-8", errors="replace").decode("utf-8"): _rfc8785_safe(entry)
            for key, entry in value.items()
        }
    raise ValueError("value must contain JSON values only")


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
