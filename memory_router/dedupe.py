from __future__ import annotations

import re
import unicodedata
from typing import Any
from .canonical import canonical_json, sha256_hex

ORDER_INSENSITIVE_ARRAY_KEYS = {"document_tags", "tags", "types"}

def request_dedupe_key(kind: str, writer_id: str | None, target: str | None, payload: Any) -> str:
    return sha256_hex(canonical_json({"kind":kind,"writer_id":writer_id,"target":target,"payload":payload}))

def security_event_dedupe_key(method: str, path: str) -> str:
    without_query = re.split(r"[?#]", path, maxsplit=1)[0]
    normalized = without_query.lower().rstrip("/") or "/"
    return f"{method.upper()}:{normalized}"

class SecurityEventIdentityCap:
    def __init__(self) -> None:
        self.seen: set[str] = set()
    def resolve(self, writer_id: str | None, base_key: str) -> str:
        scoped = f"{writer_id or 'anonymous'}:{base_key}"
        if scoped in self.seen:
            return scoped
        if len(self.seen) >= 64:
            return "aggregate"
        self.seen.add(scoped)
        return scoped

def request_family_identity(kind: str, reason: str, writer_id: str | None, payload: Any) -> tuple[str, str] | None:
    if kind not in {"retain_request", "recall_request"}:
        return None
    scope_owner = "unknown-writer" if reason == "unknown_writer" else writer_id or "anonymous"
    base = {"kind":kind,"reason":reason}
    normalized = sha256_hex(canonical_json({**base,"payload":_normalize(payload)}))
    structural = sha256_hex(canonical_json({**base,"payload":_shape(payload)}))
    return f"{kind}:{reason}:{scope_owner}", sha256_hex(f"{normalized}:{structural}")

def _normalize(value: Any, key: str | None = None) -> Any:
    if isinstance(value, str):
        return " ".join(unicodedata.normalize("NFKC", value).strip().lower().split())
    if isinstance(value, list):
        result = [_normalize(item) for item in value]
        return sorted(result, key=canonical_json) if key in ORDER_INSENSITIVE_ARRAY_KEYS else result
    if isinstance(value, dict):
        return {entry_key:_normalize(entry, entry_key) for entry_key,entry in value.items()}
    return value

def _shape(value: Any, key: str | None = None) -> Any:
    if isinstance(value, str):
        normalized = " ".join(unicodedata.normalize("NFKC", value).strip().lower().split())
        tokens = 0 if not normalized else len(normalized.split())
        return {"text_length_bucket":len(normalized)//32,"token_count_bucket":tokens//4}
    if isinstance(value, list):
        result = [_shape(item) for item in value]
        return sorted(result, key=canonical_json) if key in ORDER_INSENSITIVE_ARRAY_KEYS else result
    if isinstance(value, dict):
        return {entry_key:_shape(entry, entry_key) for entry_key,entry in value.items()}
    if value is None:
        return "object"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int,float)):
        return "number"
    return type(value).__name__
