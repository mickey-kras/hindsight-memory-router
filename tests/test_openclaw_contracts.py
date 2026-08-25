from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from memory_router.openclaw_contracts import validate_openclaw_response

STRICT_STRING_CASES: tuple[
    tuple[str, str, str | None, dict[str, Any], tuple[str | int, ...]], ...
] = (
    *(
        (
            "PUT",
            "",
            None,
            {"bank_id": "bank", "name": "Bank", "disposition": {}, "mission": "Help"},
            (field,),
        )
        for field in ("bank_id", "name", "mission")
    ),
    (
        "PATCH",
        "config",
        None,
        {"bank_id": "bank", "config": {}, "overrides": {}},
        ("bank_id",),
    ),
    *(
        (
            "GET",
            "mental-models",
            None,
            {"items": [{"id": "model", "bank_id": "bank", "name": "Model"}]},
            ("items", 0, field),
        )
        for field in ("id", "bank_id", "name")
    ),
    *(
        (
            "POST",
            "mental-models",
            None,
            {"operation_id": "operation", "mental_model_id": "model"},
            (field,),
        )
        for field in ("operation_id", "mental_model_id")
    ),
    *(
        (
            method,
            "mental-models",
            "model",
            {"id": "model", "bank_id": "bank", "name": "Model"},
            (field,),
        )
        for method in ("GET", "PATCH")
        for field in ("id", "bank_id", "name")
    ),
    ("POST", "reflect", None, {"text": "reflection"}, ("text",)),
)


def _replace_path(value: dict[str, Any], path: tuple[str | int, ...], replacement: Any) -> None:
    target: Any = value
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = replacement


@pytest.mark.parametrize(
    ("method", "resource", "mental_model_id", "response", "field_path"),
    STRICT_STRING_CASES,
)
def test_every_strict_string_field_rejects_coercible_values(
    method: str,
    resource: str,
    mental_model_id: str | None,
    response: dict[str, Any],
    field_path: tuple[str | int, ...],
) -> None:
    invalid = deepcopy(response)
    _replace_path(invalid, field_path, b"coercible")

    with pytest.raises(ValueError, match="invalid Hindsight OpenClaw response"):
        validate_openclaw_response(method, resource, mental_model_id, invalid)


def test_delete_mental_model_rejects_wrong_response_type() -> None:
    with pytest.raises(ValueError, match="mental model delete response"):
        validate_openclaw_response("DELETE", "mental-models", "model", [])


def test_unsupported_strict_contract_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported OpenClaw response contract"):
        validate_openclaw_response("GET", "unknown", None, {})
