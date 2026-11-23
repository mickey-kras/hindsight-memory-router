from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .principals import PrincipalRegistry


def https_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or "%" in parsed.path
        or any(part in {".", ".."} for part in parsed.path.split("/"))
        or parsed.path.endswith("//")
        or any(ord(char) <= 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("expected an HTTPS URL without credentials, query, or fragment")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid HTTPS port")
    return value


class HumanAuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    router_url: str = Field(max_length=2048)
    issuer: str = Field(max_length=2048)
    client_id: str = Field(min_length=1, max_length=256)
    subjects: dict[str, str] = Field(min_length=1, max_length=10000)
    # Both lifetimes enable router-issued refresh tokens; omit both to require hourly login.
    session_idle_seconds: int | None = Field(None, ge=3600, le=604_800)
    session_absolute_seconds: int | None = Field(None, ge=3600, le=2_592_000)

    @field_validator("router_url", "issuer")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return https_url(value)

    @field_validator("router_url")
    @classmethod
    def canonical_router_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if value.endswith("/") or parsed.netloc != parsed.netloc.lower() or parsed.port == 443:
            raise ValueError("router_url must be canonical without trailing slash or default port")
        return value

    @model_validator(mode="after")
    def paired_session_lifetimes(self) -> HumanAuthConfig:
        idle, absolute = self.session_idle_seconds, self.session_absolute_seconds
        if (idle is None) != (absolute is None) or (
            idle is not None and absolute is not None and idle > absolute
        ):
            raise ValueError("session lifetimes must be set together with idle <= absolute")
        return self


def load_human_config(path: str, registry: PrincipalRegistry) -> HumanAuthConfig:
    try:
        config = HumanAuthConfig.model_validate_json(Path(path).read_bytes())
        for subject, principal_id in config.subjects.items():
            principal = registry.principals.get(principal_id)
            if (
                not subject
                or len(subject) > 255
                or principal is None
                or principal.source != "human"
                or principal_id == "control-plane"
            ):
                raise ValueError("invalid human identity mapping")
    except (OSError, ValueError) as exc:
        raise RuntimeError("invalid human authentication configuration") from exc
    return config


def generation_for(config: HumanAuthConfig, registry: PrincipalRegistry) -> str:
    # Omitting unset options keeps generations of configurations without refresh unchanged.
    policy = {
        "human_auth": config.model_dump(exclude_none=True),
        "registry": registry.model_dump(mode="json"),
    }
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
