from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .facade_routes import FacadeRoute

# Authorization scope vocabulary. Every authenticated surface maps to exactly
# one scope; grants are per (principal, bank) and evaluation is default deny.
SCOPE_BANKS_LIST = "banks:list"
SCOPE_BANKS_READ = "banks:read"
SCOPE_BANKS_MANAGE = "banks:manage"
SCOPE_MEMORIES_RETAIN = "memories:retain"
SCOPE_MEMORIES_RECALL = "memories:recall"
SCOPE_MEMORIES_READ = "memories:read"
SCOPE_MEMORIES_WRITE = "memories:write"
SCOPE_REFLECT_RUN = "reflect:run"
SCOPE_OPERATIONS_MANAGE = "operations:manage"
SCOPE_VOCABULARY = frozenset(
    {
        SCOPE_BANKS_LIST,
        SCOPE_BANKS_READ,
        SCOPE_BANKS_MANAGE,
        SCOPE_MEMORIES_RETAIN,
        SCOPE_MEMORIES_RECALL,
        SCOPE_MEMORIES_READ,
        SCOPE_MEMORIES_WRITE,
        SCOPE_REFLECT_RUN,
        SCOPE_OPERATIONS_MANAGE,
    }
)

# Optional anti-impersonation header: when present it must name the
# authenticated principal. Identity never comes from this header alone.
CLAIMED_AGENT_HEADER = "x-memory-router-agent"

TOKEN_PREFIX = "mr_"  # noqa: S105 - token format prefix, not a credential
PRINCIPAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SECRET_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_BEARER_PREFIX = "Bearer "

_BANK_LEVEL_READ_RESOURCES = frozenset(
    {
        "stats",
        "stats/memories-timeseries",
        "tags",
        "graph",
        "audit-logs",
        "audit-logs/stats",
        "llm-requests",
        "llm-requests/stats",
    }
)
_BANK_MANAGE_RESOURCES = frozenset({"consolidate", "consolidation/recover"})


class PrincipalKey(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1)
    sha256: str


class PrincipalGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    bank: str = Field(min_length=1)
    scopes: list[str] = Field(min_length=1)


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    keys: list[PrincipalKey] = Field(min_length=1)
    grants: list[PrincipalGrant] = []


class PrincipalRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    principals: dict[str, Principal] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class PrincipalSession:
    principal_id: str
    key_id: str
    grants: tuple[PrincipalGrant, ...]


def load_principal_registry(path: str) -> PrincipalRegistry:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("principal registry is not readable JSON") from exc
    try:
        registry = PrincipalRegistry.model_validate(value)
    except ValidationError as exc:
        raise RuntimeError("invalid principal registry") from exc
    seen_key_ids: set[str] = set()
    for principal_id, principal in registry.principals.items():
        if principal_id in {".", ".."} or not PRINCIPAL_ID_PATTERN.fullmatch(principal_id):
            raise RuntimeError(
                "principal id must match [A-Za-z0-9._:-]{1,128} and cannot be . or .."
            )
        for key in principal.keys:
            if not KEY_ID_PATTERN.fullmatch(key.id):
                raise RuntimeError("key id must match [A-Za-z0-9._-]{1,64}")
            if key.id in seen_key_ids:
                raise RuntimeError("key ids must be unique across principals")
            seen_key_ids.add(key.id)
            if not DIGEST_PATTERN.fullmatch(key.sha256):
                raise RuntimeError("key sha256 must be 64 lowercase hex characters")
        for grant in principal.grants:
            if grant.bank in {".", ".."} or not PRINCIPAL_ID_PATTERN.fullmatch(grant.bank):
                raise RuntimeError(
                    "grant bank must match [A-Za-z0-9._:-]{1,128} and cannot be . or .."
                )
            unknown = sorted(set(grant.scopes) - SCOPE_VOCABULARY)
            if unknown:
                raise RuntimeError(f"unknown grant scope: {unknown[0]}")
    return registry


def _bearer_token(authorization: str | None) -> str | None:
    if authorization is None or not authorization.startswith(_BEARER_PREFIX):
        return None
    token = authorization[len(_BEARER_PREFIX) :]
    return token or None


def _parse_token(token: str) -> tuple[str, str] | None:
    if not token.startswith(TOKEN_PREFIX):
        return None
    key_id, separator, secret = token[len(TOKEN_PREFIX) :].rpartition("_")
    if not separator:
        return None
    if not KEY_ID_PATTERN.fullmatch(key_id) or not SECRET_PATTERN.fullmatch(secret):
        return None
    return key_id, secret


def token_digest(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("ascii")).digest()


class PrincipalResolver:
    """Authenticates mr_<key-id>_<secret> tokens and evaluates grants.

    The registry stores SHA-256 digests only; presented secrets are hashed and
    compared in constant time. Key-id lookup is O(1); overlapping keys per
    principal support rotation without downtime.
    """

    def __init__(self, registry: PrincipalRegistry) -> None:
        self.registry = registry
        self._index: dict[str, tuple[str, bytes]] = {
            key.id: (principal_id, bytes.fromhex(key.sha256))
            for principal_id, principal in registry.principals.items()
            for key in principal.keys
        }

    def authenticate(self, authorization: str | None) -> PrincipalSession | None:
        parsed = _parse_token(_bearer_token(authorization) or "")
        if parsed is None:
            return None
        key_id, secret = parsed
        entry = self._index.get(key_id)
        if entry is None:
            return None
        principal_id, digest = entry
        if not hmac.compare_digest(token_digest(secret), digest):
            return None
        principal = self.registry.principals[principal_id]
        return PrincipalSession(principal_id, key_id, tuple(principal.grants))

    @staticmethod
    def authorize(session: PrincipalSession, scope: str, bank: str) -> bool:
        return any(grant.bank == bank and scope in grant.scopes for grant in session.grants)

    @staticmethod
    def list_banks(session: PrincipalSession) -> list[str]:
        return sorted({grant.bank for grant in session.grants if SCOPE_BANKS_LIST in grant.scopes})


def facade_scope(route: FacadeRoute) -> str:
    resource = route.resource
    if route.template == "reflect":
        return SCOPE_REFLECT_RUN
    if route.template == "memories/dry-run-extract":
        return SCOPE_MEMORIES_RETAIN
    if not resource or resource in _BANK_MANAGE_RESOURCES:
        return SCOPE_BANKS_MANAGE
    if resource == "config":
        return SCOPE_BANKS_READ if route.read else SCOPE_BANKS_MANAGE
    if resource in _BANK_LEVEL_READ_RESOURCES:
        return SCOPE_BANKS_READ
    if resource == "operations" or resource.startswith("operations/"):
        return SCOPE_BANKS_READ if route.read else SCOPE_OPERATIONS_MANAGE
    return SCOPE_MEMORIES_READ if route.read else SCOPE_MEMORIES_WRITE
