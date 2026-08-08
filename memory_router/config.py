from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Mapping

DEFAULT_DATABASE_URL = "sqlite:./data/quarantine.db"


def _int(env: Mapping[str, str], name: str, default: int, minimum: int = 0) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer; received {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}; received {value}")
    return value


def _bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    normalized = raw.strip().lower()
    if normalized in {"true", "1"}:
        return True
    if normalized in {"false", "0"}:
        return False
    raise ValueError(f"{name} must be true or false; received {raw!r}")


@dataclass(frozen=True, slots=True)
class HindsightLimitConfig:
    retain_writer_max: int = 30
    retain_global_max: int = 300
    recall_writer_max: int = 120
    recall_global_max: int = 1200
    rate_limit_window_ms: int = 60_000
    max_retain_items: int = 100
    max_retain_content_bytes: int = 524_288
    max_recall_query_bytes: int = 32_768
    max_recall_max_tokens: int = 8_192


@dataclass(frozen=True, slots=True)
class QuarantineLimits:
    max_item_bytes: int = 1_048_576
    max_pending_items: int = 1_000
    max_pending_items_per_writer: int = 50
    max_encrypted_bytes: int = 104_857_600
    rate_limit_max: int = 30
    rate_limit_window_ms: int = 60_000
    rate_limit_global_max: int = 300
    distinct_family_limit_max: int = 10
    requarantine_ops_max: int = 1_000
    item_ttl_days: int = 30


@dataclass(frozen=True, slots=True)
class Settings:
    port: int
    allow_anonymous: bool
    hindsight_base_url: str
    hindsight_api_key: str | None
    hindsight_timeout_ms: int
    registry_path: str | None
    quarantine_public_key: str
    quarantine_database_url: str
    max_postpones: int
    sweep_interval_seconds: int
    event_retention_days: int
    max_body_bytes: int
    admin_rate_read_max: int
    admin_rate_write_max: int
    admin_rate_window_ms: int
    deployment_mode: str
    external_admin_rate_limit: bool
    router_token: str | None
    admin_legacy_token: str | None
    admin_read_token: str | None
    admin_review_token: str | None
    admin_cleanup_token: str | None
    hindsight_limits: HindsightLimitConfig
    quarantine_limits: QuarantineLimits

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environment is None else environment
        mode = env.get("MEMORY_ROUTER_DEPLOYMENT_MODE", "single")
        if mode not in {"single", "cluster"}:
            raise ValueError(
                f'MEMORY_ROUTER_DEPLOYMENT_MODE must be single or cluster; received {mode!r}'
            )
        db = env.get("QUARANTINE_DATABASE_URL", DEFAULT_DATABASE_URL)
        external_admin = _bool(env, "MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT", False)
        if mode == "cluster":
            if not is_postgres_url(db):
                raise ValueError(
                    "cluster deployment mode requires a PostgreSQL QUARANTINE_DATABASE_URL"
                )
            if not external_admin:
                raise ValueError(
                    "cluster deployment mode requires MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true "
                    "because built-in admin throttling is process-local"
                )
        elif external_admin:
            sys.stderr.write(
                "memory-router WARNING: MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true in single mode; "
                "ensure the external limiter is actually present\n"
            )
        assert_no_private_key_environment(env)
        return cls(
            port=_int(env, "MEMORY_ROUTER_PORT", 8890, 1),
            allow_anonymous=_bool(env, "MEMORY_ROUTER_ALLOW_ANONYMOUS", False),
            hindsight_base_url=env.get("HINDSIGHT_BASE_URL", "http://hindsight:8888"),
            hindsight_api_key=env.get("HINDSIGHT_API_KEY") or None,
            hindsight_timeout_ms=_int(env, "HINDSIGHT_TIMEOUT_MS", 10_000, 1),
            registry_path=env.get("MEMORY_ROUTER_REGISTRY") or None,
            quarantine_public_key=env.get("QUARANTINE_PUBLIC_KEY", ""),
            quarantine_database_url=db,
            max_postpones=_int(env, "QUARANTINE_MAX_POSTPONES", 3, 0),
            sweep_interval_seconds=_int(env, "QUARANTINE_SWEEP_INTERVAL_SECONDS", 3600, 0),
            event_retention_days=_int(env, "QUARANTINE_EVENT_RETENTION_DAYS", 90, 0),
            max_body_bytes=_int(env, "MEMORY_ROUTER_MAX_BODY_BYTES", 1_048_576, 1),
            admin_rate_read_max=_int(env, "MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX", 120, 1),
            admin_rate_write_max=_int(env, "MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX", 30, 1),
            admin_rate_window_ms=_int(env, "MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS", 60_000, 1),
            deployment_mode=mode,
            external_admin_rate_limit=external_admin,
            router_token=env.get("MEMORY_ROUTER_TOKEN") or None,
            admin_legacy_token=env.get("MEMORY_ROUTER_ADMIN_TOKEN") or None,
            admin_read_token=env.get("MEMORY_ROUTER_ADMIN_READ_TOKEN") or None,
            admin_review_token=env.get("MEMORY_ROUTER_ADMIN_REVIEW_TOKEN") or None,
            admin_cleanup_token=env.get("MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN") or None,
            hindsight_limits=HindsightLimitConfig(
                retain_writer_max=_int(env, "HINDSIGHT_RETAIN_RATE_LIMIT_WRITER_MAX", 30, 1),
                retain_global_max=_int(env, "HINDSIGHT_RETAIN_RATE_LIMIT_GLOBAL_MAX", 300, 1),
                recall_writer_max=_int(env, "HINDSIGHT_RECALL_RATE_LIMIT_WRITER_MAX", 120, 1),
                recall_global_max=_int(env, "HINDSIGHT_RECALL_RATE_LIMIT_GLOBAL_MAX", 1200, 1),
                rate_limit_window_ms=_int(env, "HINDSIGHT_RATE_LIMIT_WINDOW_MS", 60_000, 1),
                max_retain_items=_int(env, "HINDSIGHT_RETAIN_MAX_ITEMS", 100, 1),
                max_retain_content_bytes=_int(
                    env, "HINDSIGHT_RETAIN_MAX_CONTENT_BYTES", 524_288, 1
                ),
                max_recall_query_bytes=_int(
                    env, "HINDSIGHT_RECALL_MAX_QUERY_BYTES", 32_768, 1
                ),
                max_recall_max_tokens=_int(env, "HINDSIGHT_RECALL_MAX_TOKENS", 8_192, 1),
            ),
            quarantine_limits=QuarantineLimits(
                max_item_bytes=_int(env, "QUARANTINE_MAX_ITEM_BYTES", 1_048_576, 1),
                max_pending_items=_int(env, "QUARANTINE_MAX_PENDING_ITEMS", 1_000, 1),
                max_pending_items_per_writer=_int(
                    env, "QUARANTINE_MAX_PENDING_ITEMS_PER_WRITER", 50, 0
                ),
                max_encrypted_bytes=_int(
                    env, "QUARANTINE_MAX_ENCRYPTED_BYTES", 104_857_600, 1
                ),
                rate_limit_max=_int(env, "QUARANTINE_RATE_LIMIT_MAX", 30, 0),
                rate_limit_window_ms=_int(env, "QUARANTINE_RATE_LIMIT_WINDOW_MS", 60_000, 1),
                rate_limit_global_max=_int(env, "QUARANTINE_RATE_LIMIT_GLOBAL_MAX", 300, 0),
                distinct_family_limit_max=_int(
                    env, "QUARANTINE_DISTINCT_FAMILY_LIMIT_MAX", 10, 0
                ),
                requarantine_ops_max=_int(env, "QUARANTINE_REQUARANTINE_OPS_MAX", 1_000, 0),
                item_ttl_days=_int(env, "QUARANTINE_ITEM_TTL_DAYS", 30, 0),
            ),
        )


def is_postgres_url(value: str) -> bool:
    return value.startswith("postgres://") or value.startswith("postgresql://")


def assert_no_private_key_environment(environment: Mapping[str, str]) -> None:
    injected = next((name for name in environment if name.startswith("QUARANTINE_PRIVATE_KEY")), None)
    if injected:
        raise ValueError(f"{injected} must not be available to the memory-router process")


def warn_auth(settings: Settings) -> None:
    if not settings.router_token:
        if settings.allow_anonymous:
            sys.stderr.write(
                "memory-router WARNING: MEMORY_ROUTER_ALLOW_ANONYMOUS=true; Development only\n"
            )
        else:
            sys.stderr.write(
                "memory-router WARNING: MEMORY_ROUTER_TOKEN is not set; router endpoints fail-closed\n"
            )
    if settings.admin_legacy_token:
        sys.stderr.write(
            "memory-router WARNING: legacy admin migration superuser is active; migrate clients "
            "to scoped tokens and unset MEMORY_ROUTER_ADMIN_TOKEN\n"
        )
        return
    if not settings.admin_read_token and not settings.admin_review_token:
        sys.stderr.write(
            "memory-router WARNING: admin read token is not set; admin read endpoints fail-closed\n"
        )
    if not settings.admin_review_token:
        sys.stderr.write(
            "memory-router WARNING: admin review token is not set; review endpoints fail-closed\n"
        )
    if not settings.admin_cleanup_token:
        sys.stderr.write(
            "memory-router WARNING: admin cleanup token is not set; cleanup endpoint fails-closed\n"
        )
