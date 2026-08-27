from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, StrictStr, ValidationError


class _Response(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)


class BankProfileResponse(_Response):
    bank_id: StrictStr
    name: StrictStr
    disposition: dict[str, Any]
    mission: StrictStr


class BankConfigResponse(_Response):
    bank_id: StrictStr
    config: dict[str, Any]
    overrides: dict[str, Any]


class MentalModelResponse(_Response):
    id: StrictStr
    bank_id: StrictStr
    name: StrictStr


class MentalModelListResponse(_Response):
    items: list[MentalModelResponse]


class CreateMentalModelResponse(_Response):
    operation_id: StrictStr
    mental_model_id: StrictStr | None = None


class ReflectResponse(_Response):
    text: StrictStr


def validate_facade_response(
    value: Any, response: str = "object", *, allow_empty: bool = False
) -> None:
    expected = dict if response == "object" else list
    if (allow_empty and value is None) or isinstance(value, expected):
        return
    raise ValueError(f"facade response must be a JSON {response}")


def validate_openclaw_response(
    method: str, resource: str, mental_model_id: str | None, value: Any
) -> None:
    if method == "DELETE" and resource == "mental-models" and mental_model_id is not None:
        if value is None or isinstance(value, dict):
            return
        raise ValueError("mental model delete response must be empty or an object")

    model: type[_Response]
    if method == "PUT" and resource == "":
        model = BankProfileResponse
    elif method == "PATCH" and resource == "config":
        model = BankConfigResponse
    elif method == "GET" and resource == "mental-models" and mental_model_id is None:
        model = MentalModelListResponse
    elif method == "POST" and resource == "mental-models" and mental_model_id is None:
        model = CreateMentalModelResponse
    elif method in {"GET", "PATCH"} and resource == "mental-models" and mental_model_id is not None:
        model = MentalModelResponse
    elif method == "POST" and resource == "reflect":
        model = ReflectResponse
    else:
        raise ValueError("unsupported OpenClaw response contract")

    try:
        model.model_validate(value)
    except ValidationError as exc:
        raise ValueError("invalid Hindsight OpenClaw response") from exc
