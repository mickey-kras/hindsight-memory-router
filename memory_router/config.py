from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from pydantic import ValidationError

from .models import WriterRegistry

logger = logging.getLogger(__name__)

DEFAULT_REGISTRY = WriterRegistry.model_validate(
    {
        "writers": {
            "main": {
                "role": "default",
                "source": "application",
                "write_bank": "main",
                "read_banks": ["main"],
            }
        },
        "defaults": {
            "unknown_writer_action": "review_queue",
            "suspicious_content_action": "review_queue",
        },
    }
)


def integer_env(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        value = default
    else:
        try:
            value = int(raw, 10)
        except ValueError as exc:
            raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")
    return value


def boolean_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise RuntimeError(f"{name} must be true or false")


def load_registry(path: str | None = None) -> WriterRegistry:
    if not path:
        return DEFAULT_REGISTRY.model_copy(deep=True)
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        registry = WriterRegistry.model_validate(value)
    except ValidationError as exc:
        raise RuntimeError("invalid writer registry") from exc
    for writer_id in registry.writers:
        if not writer_id.strip():
            raise RuntimeError("writer id cannot be empty")
    return registry


def assert_no_private_key_environment() -> None:
    injected = next(
        (name for name in os.environ if name.startswith("QUARANTINE_PRIVATE_KEY")), None
    )
    if injected:
        raise RuntimeError(f"{injected} must not be available to the memory-router process")


def assert_auth_environment() -> None:
    router_token = os.environ.get("MEMORY_ROUTER_TOKEN")
    anonymous = boolean_env("MEMORY_ROUTER_ALLOW_ANONYMOUS", False)
    if not router_token:
        if anonymous:
            logger.warning("MEMORY_ROUTER_ALLOW_ANONYMOUS=true; Development only")
        else:
            logger.warning("MEMORY_ROUTER_TOKEN is not set; router endpoints fail-closed")
    legacy = os.environ.get("MEMORY_ROUTER_ADMIN_TOKEN")
    if legacy:
        logger.warning(
            "legacy admin migration superuser is active; migrate clients to scoped tokens and unset MEMORY_ROUTER_ADMIN_TOKEN"
        )
        return
    if not os.environ.get("MEMORY_ROUTER_ADMIN_READ_TOKEN") and not os.environ.get(
        "MEMORY_ROUTER_ADMIN_REVIEW_TOKEN"
    ):
        logger.warning("admin read token is not set; admin read endpoints fail-closed")
    if not os.environ.get("MEMORY_ROUTER_ADMIN_REVIEW_TOKEN"):
        logger.warning("admin review token is not set; review endpoints fail-closed")
    if not os.environ.get("MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN"):
        logger.warning("admin cleanup token is not set; cleanup endpoint fails-closed")


def assert_deployment_mode(database_url: str) -> None:
    mode = os.environ.get("MEMORY_ROUTER_DEPLOYMENT_MODE", "single")
    external_admin = boolean_env("MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT", False)
    if mode not in {"single", "cluster"}:
        raise RuntimeError("MEMORY_ROUTER_DEPLOYMENT_MODE must be single or cluster")
    if mode == "cluster":
        if not database_url.startswith(("postgres://", "postgresql://")):
            raise RuntimeError("cluster deployment requires PostgreSQL quarantine storage")
        if not external_admin:
            raise RuntimeError(
                "cluster deployment requires MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true"
            )
