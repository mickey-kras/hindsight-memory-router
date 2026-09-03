from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .facade_routes import FacadeRoute

# Authorization scope vocabulary. Every authenticated surface maps to exactly
# one scope; grants are per (principal, bank) and evaluation is default deny.
# The authorizer supports all nine scopes generically; quarantine scopes are
# grantable but not wired to endpoints (quarantine administration keeps its
# separate admin tokens).
SCOPE_BANK_LIST = "bank.list"
SCOPE_MEMORY_RECALL = "memory.recall"
SCOPE_MEMORY_RETAIN = "memory.retain"
SCOPE_MEMORY_REFLECT = "memory.reflect"
SCOPE_BANK_CONFIG_READ = "bank.config.read"
SCOPE_BANK_CONFIG_WRITE = "bank.config.write"
SCOPE_QUARANTINE_REVIEW = "quarantine.review"
SCOPE_QUARANTINE_DECIDE = "quarantine.decide"
SCOPE_BANK_ADMIN = "bank.admin"
SCOPE_VOCABULARY = frozenset(
    {
        SCOPE_BANK_LIST,
        SCOPE_MEMORY_RECALL,
        SCOPE_MEMORY_RETAIN,
        SCOPE_MEMORY_REFLECT,
        SCOPE_BANK_CONFIG_READ,
        SCOPE_BANK_CONFIG_WRITE,
        SCOPE_QUARANTINE_REVIEW,
        SCOPE_QUARANTINE_DECIDE,
        SCOPE_BANK_ADMIN,
    }
)

# Optional anti-impersonation header: when present it must name the
# authenticated principal. Identity never comes from this header alone.
CLAIMED_AGENT_HEADER = "x-memory-router-agent"

TOKEN_PREFIX = "mr_"  # noqa: S105  # nosec B105 - token format prefix, not a credential
PRINCIPAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SECRET_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_BEARER_PREFIX = "Bearer "

# Compared against tokens with an unknown key ID so the verification path does
# not short-circuit before the digest comparison.
_DUMMY_DIGEST = hashlib.sha256(b"memory-router:unknown-key").digest()

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
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    @field_validator("created_at", "expires_at", "revoked_at", mode="before")
    @classmethod
    def parse_timestamp(cls, value: object) -> object:
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError as exc:
                raise ValueError("key timestamps must be ISO 8601") from exc
        return value

    @field_validator("created_at", "expires_at", "revoked_at")
    @classmethod
    def timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("key timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def expiry_after_creation(self) -> PrincipalKey:
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        return self


class PrincipalGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    bank: str = Field(min_length=1)
    scopes: list[str] = Field(min_length=1)


LIMIT_OPERATIONS = ("recall", "retain", "reflect", "config", "admin")
LimitOperation = Literal["recall", "retain", "reflect", "config", "admin"]


class PrincipalOperationLimit(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    rate_limit_max: int | None = Field(None, ge=1)
    rate_limit_window_ms: int | None = Field(None, ge=1)
    concurrency_max: int | None = Field(None, ge=1)
    max_body_bytes: int | None = Field(None, ge=1)


class PrincipalLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    recall: PrincipalOperationLimit | None = None
    retain: PrincipalOperationLimit | None = None
    reflect: PrincipalOperationLimit | None = None
    config: PrincipalOperationLimit | None = None
    admin: PrincipalOperationLimit | None = None


class PrincipalRegistryDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    limits: PrincipalLimits = Field(default_factory=PrincipalLimits)


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    keys: list[PrincipalKey] = Field(min_length=1)
    grants: list[PrincipalGrant] = Field(default_factory=list)
    limits: PrincipalLimits = Field(default_factory=PrincipalLimits)


class PrincipalRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    principals: dict[str, Principal] = Field(min_length=1)
    defaults: PrincipalRegistryDefaults = Field(default_factory=PrincipalRegistryDefaults)


@dataclass(frozen=True, slots=True)
class ResolvedPrincipalLimit:
    rate_limit_max: int
    rate_limit_window_ms: int
    concurrency_max: int
    max_body_bytes: int


_BUILTIN_LIMITS: dict[LimitOperation, ResolvedPrincipalLimit] = {
    "recall": ResolvedPrincipalLimit(120, 60_000, 4, 32_768),
    "retain": ResolvedPrincipalLimit(30, 60_000, 2, 524_288),
    "reflect": ResolvedPrincipalLimit(30, 60_000, 2, 32_768),
    "config": ResolvedPrincipalLimit(60, 60_000, 2, 131_072),
    "admin": ResolvedPrincipalLimit(10, 60_000, 1, 131_072),
}


@dataclass(frozen=True, slots=True)
class PrincipalSession:
    principal_id: str
    key_id: str
    grants: tuple[PrincipalGrant, ...]
    limits: dict[LimitOperation, ResolvedPrincipalLimit]


@dataclass(frozen=True, slots=True)
class Authentication:
    """Token verification outcome; distinct statuses feed audit and metrics."""

    status: Literal["ok", "invalid-format", "unknown-key", "wrong-secret", "expired", "revoked"]
    session: PrincipalSession | None = None


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
            if len(grant.scopes) != len(set(grant.scopes)):
                raise RuntimeError("grant scopes must be unique")
        grant_banks = [grant.bank for grant in principal.grants]
        if len(grant_banks) != len(set(grant_banks)):
            raise RuntimeError("grant banks must be unique per principal")
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
    compared in constant time, including tokens with an unknown key ID (a dummy
    digest keeps the comparison path identical). Key-id lookup is O(1);
    overlapping keys per principal support rotation without downtime, and
    expires_at/revoked_at retire keys without deleting their audit history.
    """

    def __init__(self, registry: PrincipalRegistry) -> None:
        self.registry = registry
        self._index: dict[str, tuple[str, PrincipalKey]] = {
            key.id: (principal_id, key)
            for principal_id, principal in registry.principals.items()
            for key in principal.keys
        }

    @staticmethod
    def _merge_limit(
        base: ResolvedPrincipalLimit, override: PrincipalOperationLimit | None
    ) -> ResolvedPrincipalLimit:
        if override is None:
            return base
        return ResolvedPrincipalLimit(
            rate_limit_max=override.rate_limit_max or base.rate_limit_max,
            rate_limit_window_ms=override.rate_limit_window_ms or base.rate_limit_window_ms,
            concurrency_max=override.concurrency_max or base.concurrency_max,
            max_body_bytes=override.max_body_bytes or base.max_body_bytes,
        )

    def _limits_for(self, principal: Principal) -> dict[LimitOperation, ResolvedPrincipalLimit]:
        resolved: dict[LimitOperation, ResolvedPrincipalLimit] = {}
        defaults = self.registry.defaults.limits
        for operation in LIMIT_OPERATIONS:
            typed_operation = cast(LimitOperation, operation)
            value = self._merge_limit(
                _BUILTIN_LIMITS[typed_operation], getattr(defaults, operation)
            )
            resolved[typed_operation] = self._merge_limit(
                value, getattr(principal.limits, operation)
            )
        return resolved

    def authenticate(
        self, authorization: str | None, *, now: datetime | None = None
    ) -> Authentication:
        parsed = _parse_token(_bearer_token(authorization) or "")
        if parsed is None:
            return Authentication("invalid-format")
        key_id, secret = parsed
        entry = self._index.get(key_id)
        stored = bytes.fromhex(entry[1].sha256) if entry is not None else _DUMMY_DIGEST
        matched = hmac.compare_digest(token_digest(secret), stored)
        if entry is None:
            return Authentication("unknown-key")
        principal_id, key = entry
        if not matched:
            return Authentication("wrong-secret")
        if key.revoked_at is not None:
            return Authentication("revoked")
        moment = now if now is not None else datetime.now(UTC)
        if key.expires_at is not None and moment >= key.expires_at:
            return Authentication("expired")
        principal = self.registry.principals[principal_id]
        return Authentication(
            "ok",
            PrincipalSession(
                principal_id,
                key_id,
                tuple(principal.grants),
                self._limits_for(principal),
            ),
        )

    @staticmethod
    def authorize(session: PrincipalSession, scope: str, bank: str) -> bool:
        return any(grant.bank == bank and scope in grant.scopes for grant in session.grants)

    @staticmethod
    def list_banks(session: PrincipalSession) -> list[str]:
        return sorted({grant.bank for grant in session.grants if SCOPE_BANK_LIST in grant.scopes})


def scope_limit_operation(scope: str) -> LimitOperation:
    if scope == SCOPE_MEMORY_RECALL:
        return "recall"
    if scope == SCOPE_MEMORY_RETAIN:
        return "retain"
    if scope == SCOPE_MEMORY_REFLECT:
        return "reflect"
    if scope == SCOPE_BANK_ADMIN:
        return "admin"
    return "config"


def facade_scope(route: FacadeRoute) -> str:
    resource = route.resource
    if route.template == "reflect":
        return SCOPE_MEMORY_REFLECT
    if route.template == "memories/dry-run-extract":
        return SCOPE_MEMORY_RETAIN
    if not resource or resource in _BANK_MANAGE_RESOURCES:
        return SCOPE_BANK_ADMIN
    if resource == "config":
        return SCOPE_BANK_CONFIG_READ if route.read else SCOPE_BANK_CONFIG_WRITE
    if resource in _BANK_LEVEL_READ_RESOURCES:
        return SCOPE_BANK_CONFIG_READ
    if resource == "operations" or resource.startswith("operations/"):
        return SCOPE_BANK_CONFIG_READ if route.read else SCOPE_BANK_ADMIN
    return SCOPE_MEMORY_RECALL if route.read else SCOPE_MEMORY_RETAIN
