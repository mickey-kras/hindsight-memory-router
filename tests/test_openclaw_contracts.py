from __future__ import annotations

import pytest

from memory_router.openclaw_contracts import validate_openclaw_response


@pytest.mark.parametrize(
    ("method", "resource", "mental_model_id", "response"),
    [
        (
            "PUT",
            "",
            None,
            {"bank_id": b"bank", "name": "Bank", "disposition": {}, "mission": "Help"},
        ),
        (
            "PATCH",
            "config",
            None,
            {"bank_id": b"bank", "config": {}, "overrides": {}},
        ),
        (
            "GET",
            "mental-models",
            None,
            {"items": [{"id": b"model", "bank_id": "bank", "name": "Model"}]},
        ),
        (
            "POST",
            "mental-models",
            None,
            {"operation_id": b"operation", "mental_model_id": "model"},
        ),
        (
            "GET",
            "mental-models",
            "model",
            {"id": b"model", "bank_id": "bank", "name": "Model"},
        ),
        ("POST", "reflect", None, {"text": b"reflection"}),
    ],
)
def test_strict_response_models_reject_coercible_string_values(
    method: str,
    resource: str,
    mental_model_id: str | None,
    response: object,
) -> None:
    with pytest.raises(ValueError, match="invalid Hindsight OpenClaw response"):
        validate_openclaw_response(method, resource, mental_model_id, response)
