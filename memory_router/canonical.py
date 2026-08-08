from __future__ import annotations

import hashlib
from typing import Any

import rfc8785


def canonical_json(value: Any) -> str:
    try:
        return rfc8785.dumps(value).decode("utf-8")
    except (rfc8785.CanonicalizationError, UnicodeError, TypeError, ValueError) as exc:
        raise ValueError("value must contain JSON values only") from exc


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
