from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .models import BANK_IDS, WriterRegistry

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


def load_registry(path: str | None = None) -> WriterRegistry:
    if not path:
        return DEFAULT_REGISTRY.model_copy(deep=True)
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    return validate_registry(value)


def validate_registry(value: Any) -> WriterRegistry:
    if not isinstance(value, dict):
        raise ValueError("registry must be an object")
    if not isinstance(value.get("writers"), dict):
        raise ValueError("registry.writers must be an object")
    defaults = value.get("defaults")
    if not isinstance(defaults, dict):
        raise ValueError("registry.defaults must be an object")
    if defaults.get("unknown_writer_action") != "review_queue":
        raise ValueError("registry.defaults.unknown_writer_action must be review_queue")
    if defaults.get("suspicious_content_action") != "review_queue":
        raise ValueError("registry.defaults.suspicious_content_action must be review_queue")

    for writer_id, raw in value["writers"].items():
        if not isinstance(writer_id, str) or not writer_id.strip():
            raise ValueError("writer id cannot be empty")
        if not isinstance(raw, dict):
            raise ValueError(f"writer {writer_id} must be an object")
        for field in ("role", "source", "write_bank", "read_banks"):
            if field not in raw:
                raise ValueError(f"writer {writer_id} missing {field}")
        if not isinstance(raw["role"], str) or not raw["role"].strip():
            raise ValueError(f"writer {writer_id} missing role")
        if not isinstance(raw["source"], str) or not raw["source"].strip():
            raise ValueError(f"writer {writer_id} missing source")
        if raw["write_bank"] == "quarantine":
            raise ValueError(f"writer {writer_id} cannot write quarantine")
        if raw["write_bank"] not in BANK_IDS:
            raise ValueError(f"writer {writer_id} has invalid write_bank")
        if not isinstance(raw["read_banks"], list):
            raise ValueError(f"writer {writer_id} missing read_banks")
        if "quarantine" in raw["read_banks"]:
            raise ValueError(f"writer {writer_id} cannot read quarantine")
        if any(bank not in BANK_IDS for bank in raw["read_banks"]):
            raise ValueError(f"writer {writer_id} has invalid read_bank")
        if writer_id == "main" and "research" in raw["read_banks"]:
            raise ValueError("main writer cannot read research")
    try:
        return WriterRegistry.model_validate(value)
    except ValidationError as exc:
        raise ValueError("registry must be an object") from exc
