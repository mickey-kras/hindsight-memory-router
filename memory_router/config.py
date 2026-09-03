from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, SecretStr, ValidationError, model_validator
from pydantic_core import PydanticUseDefault
from pydantic_settings import BaseSettings, SettingsConfigDict

from .logging import log_event
from .logging_contract import WRITER_ID_PATTERN
from .models import WriterRegistry

logger = logging.getLogger(__name__)
DEFAULT_DATABASE_URL = "sqlite:./data/quarantine.db"
_INTEGER_ERROR = "must be an integer"

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


def _exact_integer(value: Any) -> int:
    if value == "":
        raise PydanticUseDefault()
    if isinstance(value, bool):
        raise ValueError(_INTEGER_ERROR)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError as exc:
            raise ValueError(_INTEGER_ERROR) from exc
    raise ValueError(_INTEGER_ERROR)


def _exact_boolean(value: Any) -> bool:
    if value == "":
        raise PydanticUseDefault()
    if isinstance(value, bool):
        return value
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError("must be true or false")


NonNegativeInt = Annotated[int, BeforeValidator(_exact_integer), Field(ge=0)]
PositiveInt = Annotated[int, BeforeValidator(_exact_integer), Field(ge=1)]
ExactBool = Annotated[bool, BeforeValidator(_exact_boolean)]


class RouterSettings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=True,
        extra="ignore",
    )

    memory_router_port: PositiveInt = Field(8890, validation_alias="MEMORY_ROUTER_PORT")
    memory_router_max_body_bytes: PositiveInt = Field(
        1_048_576, validation_alias="MEMORY_ROUTER_MAX_BODY_BYTES"
    )
    memory_router_token: SecretStr | None = Field(None, validation_alias="MEMORY_ROUTER_TOKEN")
    memory_router_allow_anonymous: ExactBool = Field(
        False, validation_alias="MEMORY_ROUTER_ALLOW_ANONYMOUS"
    )
    memory_router_admin_token: SecretStr | None = Field(
        None, validation_alias="MEMORY_ROUTER_ADMIN_TOKEN"
    )
    memory_router_admin_read_token: SecretStr | None = Field(
        None, validation_alias="MEMORY_ROUTER_ADMIN_READ_TOKEN"
    )
    memory_router_admin_review_token: SecretStr | None = Field(
        None, validation_alias="MEMORY_ROUTER_ADMIN_REVIEW_TOKEN"
    )
    memory_router_admin_cleanup_token: SecretStr | None = Field(
        None, validation_alias="MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN"
    )
    memory_router_admin_rate_limit_read_max: PositiveInt = Field(
        120, validation_alias="MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX"
    )
    memory_router_admin_rate_limit_write_max: PositiveInt = Field(
        30, validation_alias="MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX"
    )
    memory_router_admin_rate_limit_window_ms: PositiveInt = Field(
        60_000, validation_alias="MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS"
    )
    memory_router_auth_failure_rate_limit_max: PositiveInt = Field(
        120, validation_alias="MEMORY_ROUTER_AUTH_FAILURE_RATE_LIMIT_MAX"
    )
    memory_router_auth_failure_rate_limit_window_ms: PositiveInt = Field(
        60_000, validation_alias="MEMORY_ROUTER_AUTH_FAILURE_RATE_LIMIT_WINDOW_MS"
    )
    memory_router_registry: str | None = Field(None, validation_alias="MEMORY_ROUTER_REGISTRY")
    memory_router_principals: str | None = Field(None, validation_alias="MEMORY_ROUTER_PRINCIPALS")
    memory_router_principal_rate_limit_max: PositiveInt = Field(
        240, validation_alias="MEMORY_ROUTER_PRINCIPAL_RATE_LIMIT_MAX"
    )
    memory_router_principal_rate_limit_window_ms: PositiveInt = Field(
        60_000, validation_alias="MEMORY_ROUTER_PRINCIPAL_RATE_LIMIT_WINDOW_MS"
    )
    memory_router_principal_concurrency_max: PositiveInt = Field(
        8, validation_alias="MEMORY_ROUTER_PRINCIPAL_CONCURRENCY_MAX"
    )
    memory_router_deployment_mode: Literal["single", "cluster"] = Field(
        "single", validation_alias="MEMORY_ROUTER_DEPLOYMENT_MODE"
    )
    memory_router_external_admin_rate_limit: ExactBool = Field(
        False, validation_alias="MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT"
    )

    quarantine_database_url: str = Field(
        DEFAULT_DATABASE_URL,
        validation_alias="QUARANTINE_DATABASE_URL",
        exclude=True,
        repr=False,
    )
    quarantine_public_key: str = Field("", validation_alias="QUARANTINE_PUBLIC_KEY")
    quarantine_max_item_bytes: NonNegativeInt = Field(
        1_048_576, validation_alias="QUARANTINE_MAX_ITEM_BYTES"
    )
    quarantine_max_pending_items: NonNegativeInt = Field(
        1_000, validation_alias="QUARANTINE_MAX_PENDING_ITEMS"
    )
    quarantine_max_pending_items_per_writer: NonNegativeInt = Field(
        50, validation_alias="QUARANTINE_MAX_PENDING_ITEMS_PER_WRITER"
    )
    quarantine_max_encrypted_bytes: NonNegativeInt = Field(
        104_857_600, validation_alias="QUARANTINE_MAX_ENCRYPTED_BYTES"
    )
    quarantine_rate_limit_max: NonNegativeInt = Field(
        30, validation_alias="QUARANTINE_RATE_LIMIT_MAX"
    )
    quarantine_rate_limit_window_ms: NonNegativeInt = Field(
        60_000, validation_alias="QUARANTINE_RATE_LIMIT_WINDOW_MS"
    )
    quarantine_rate_limit_global_max: NonNegativeInt = Field(
        300, validation_alias="QUARANTINE_RATE_LIMIT_GLOBAL_MAX"
    )
    quarantine_distinct_family_limit_max: NonNegativeInt = Field(
        10, validation_alias="QUARANTINE_DISTINCT_FAMILY_LIMIT_MAX"
    )
    quarantine_requarantine_ops_max: NonNegativeInt = Field(
        1_000, validation_alias="QUARANTINE_REQUARANTINE_OPS_MAX"
    )
    quarantine_item_ttl_days: NonNegativeInt = Field(
        30, validation_alias="QUARANTINE_ITEM_TTL_DAYS"
    )
    quarantine_max_postpones: NonNegativeInt = Field(3, validation_alias="QUARANTINE_MAX_POSTPONES")
    quarantine_sweep_interval_seconds: NonNegativeInt = Field(
        3_600, validation_alias="QUARANTINE_SWEEP_INTERVAL_SECONDS"
    )
    quarantine_event_retention_days: NonNegativeInt = Field(
        90, validation_alias="QUARANTINE_EVENT_RETENTION_DAYS"
    )

    hindsight_base_url: str = Field("http://hindsight:8888", validation_alias="HINDSIGHT_BASE_URL")
    hindsight_api_key: SecretStr | None = Field(None, validation_alias="HINDSIGHT_API_KEY")
    hindsight_timeout_ms: PositiveInt = Field(10_000, validation_alias="HINDSIGHT_TIMEOUT_MS")
    hindsight_max_response_bytes: PositiveInt = Field(
        4 * 1024 * 1024, validation_alias="HINDSIGHT_MAX_RESPONSE_BYTES"
    )
    hindsight_retain_rate_limit_writer_max: PositiveInt = Field(
        30, validation_alias="HINDSIGHT_RETAIN_RATE_LIMIT_WRITER_MAX"
    )
    hindsight_retain_rate_limit_global_max: PositiveInt = Field(
        300, validation_alias="HINDSIGHT_RETAIN_RATE_LIMIT_GLOBAL_MAX"
    )
    hindsight_recall_rate_limit_writer_max: PositiveInt = Field(
        120, validation_alias="HINDSIGHT_RECALL_RATE_LIMIT_WRITER_MAX"
    )
    hindsight_recall_rate_limit_global_max: PositiveInt = Field(
        1_200, validation_alias="HINDSIGHT_RECALL_RATE_LIMIT_GLOBAL_MAX"
    )
    hindsight_rate_limit_window_ms: PositiveInt = Field(
        60_000, validation_alias="HINDSIGHT_RATE_LIMIT_WINDOW_MS"
    )
    hindsight_retain_max_items: PositiveInt = Field(
        100, validation_alias="HINDSIGHT_RETAIN_MAX_ITEMS"
    )
    hindsight_retain_max_content_bytes: PositiveInt = Field(
        524_288, validation_alias="HINDSIGHT_RETAIN_MAX_CONTENT_BYTES"
    )
    hindsight_recall_max_query_bytes: PositiveInt = Field(
        32_768, validation_alias="HINDSIGHT_RECALL_MAX_QUERY_BYTES"
    )
    hindsight_recall_max_tokens: PositiveInt = Field(
        8_192, validation_alias="HINDSIGHT_RECALL_MAX_TOKENS"
    )

    @model_validator(mode="after")
    def validate_deployment(self) -> RouterSettings:
        if (
            self.memory_router_deployment_mode == "cluster"
            and not self.quarantine_database_url.startswith(("postgres://", "postgresql://"))
        ):
            raise ValueError("cluster deployment requires PostgreSQL quarantine storage")
        if (
            self.memory_router_deployment_mode == "cluster"
            and not self.memory_router_external_admin_rate_limit
        ):
            raise ValueError(
                "cluster deployment requires MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true"
            )
        return self


def _settings_error_message(exc: ValidationError) -> str:
    error = exc.errors()[0]
    location = error.get("loc", ())
    name = str(location[0]) if location else "memory-router settings"
    error_type = error.get("type")
    context = error.get("ctx")
    if error_type == "greater_than_equal" and isinstance(context, dict):
        return f"{name} must be >= {context['ge']}"
    if name == "MEMORY_ROUTER_DEPLOYMENT_MODE" and error_type == "literal_error":
        return "MEMORY_ROUTER_DEPLOYMENT_MODE must be single or cluster"
    if isinstance(context, dict) and isinstance(context.get("error"), ValueError):
        detail = str(context["error"])
        return detail if not location else f"{name} {detail}"
    return f"invalid {name}"


def _validated_settings(values: dict[str, Any]) -> RouterSettings:
    try:
        return RouterSettings(**values)
    except ValidationError as exc:
        raise RuntimeError(_settings_error_message(exc)) from None


def load_settings(*, quarantine_database_url: str | None = None) -> RouterSettings:
    values: dict[str, Any] = {}
    if quarantine_database_url is not None:
        values["QUARANTINE_DATABASE_URL"] = quarantine_database_url
    return _validated_settings(values)


def validate_settings(settings: RouterSettings) -> RouterSettings:
    values = {
        alias: getattr(settings, name)
        for name, field in RouterSettings.model_fields.items()
        if isinstance(alias := field.validation_alias, str)
    }
    return _validated_settings(values)


def secret_value(value: SecretStr | None) -> str | None:
    return value.get_secret_value() if value is not None else None


def load_registry(path: str | None = None) -> WriterRegistry:
    if not path:
        return DEFAULT_REGISTRY.model_copy(deep=True)
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        registry = WriterRegistry.model_validate(value)
    except ValidationError as exc:
        raise RuntimeError("invalid writer registry") from exc
    for writer_id in registry.writers:
        if writer_id in {".", ".."} or not WRITER_ID_PATTERN.fullmatch(writer_id):
            raise RuntimeError("writer id must match [A-Za-z0-9._:-]{1,128} and cannot be . or ..")
    return registry


def assert_no_private_key_environment() -> None:
    injected = next(
        (name for name in os.environ if name.startswith("QUARANTINE_PRIVATE_KEY")), None
    )
    if injected:
        raise RuntimeError(f"{injected} must not be available to the memory-router process")


def assert_auth_environment(settings: RouterSettings) -> None:
    if settings.memory_router_principals:
        if secret_value(settings.memory_router_token):
            raise RuntimeError(
                "MEMORY_ROUTER_TOKEN must be unset when MEMORY_ROUTER_PRINCIPALS is configured"
            )
        if settings.memory_router_allow_anonymous:
            raise RuntimeError(
                "MEMORY_ROUTER_ALLOW_ANONYMOUS must be false "
                "when MEMORY_ROUTER_PRINCIPALS is configured"
            )
    if not settings.memory_router_principals and not secret_value(settings.memory_router_token):
        if settings.memory_router_allow_anonymous:
            log_event(
                logger,
                "warning",
                "configuration_warning",
                operation="configuration",
                outcome="degraded",
                reason="anonymous-mode",
            )
        else:
            log_event(
                logger,
                "warning",
                "configuration_warning",
                operation="configuration",
                outcome="degraded",
                reason="router-token-missing",
            )
    if secret_value(settings.memory_router_admin_token):
        log_event(
            logger,
            "warning",
            "configuration_warning",
            operation="configuration",
            outcome="degraded",
            reason="legacy-admin-token",
        )
        return
    if not secret_value(settings.memory_router_admin_read_token) and not secret_value(
        settings.memory_router_admin_review_token
    ):
        log_event(
            logger,
            "warning",
            "configuration_warning",
            operation="configuration",
            outcome="degraded",
            reason="admin-read-token-missing",
        )
    if not secret_value(settings.memory_router_admin_review_token):
        log_event(
            logger,
            "warning",
            "configuration_warning",
            operation="configuration",
            outcome="degraded",
            reason="admin-review-token-missing",
        )
    if not secret_value(settings.memory_router_admin_cleanup_token):
        log_event(
            logger,
            "warning",
            "configuration_warning",
            operation="configuration",
            outcome="degraded",
            reason="admin-cleanup-token-missing",
        )
