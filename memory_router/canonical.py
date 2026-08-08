import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    if value is None or isinstance(value, (str, bool, int, float)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key) + ":" + canonical_json(value[key]) for key in sorted(value)) + "}"
    raise ValueError("value must contain JSON values only")


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
