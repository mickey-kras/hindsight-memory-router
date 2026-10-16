from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StrictStr, ValidationError

from .facade_routes import FacadeRoute


def facade_response_scan_input(route: FacadeRoute | None, value: object) -> object:
    if (
        route is None
        or route.method != "POST"
        or route.template != "knowledge-base/pages"
        or not isinstance(value, dict)
        or not _generated_uuid(value.get("page_id"), "kp-")
        or not _generated_uuid(value.get("mental_model_id"), "mm-")
        or "operation_id" not in value
        or (value["operation_id"] is not None and not _generated_uuid(value["operation_id"]))
    ):
        return value
    # Preserve field/byte budgets; extras keep their original content and structure.
    scanned = dict(value)
    for key in ("page_id", "mental_model_id", "operation_id"):
        identifier = value[key]
        if identifier is not None:
            scanned[key] = "." * len(identifier)
    return scanned


def _generated_uuid(value: object, prefix: str = "") -> bool:
    if not isinstance(value, str) or not value.startswith(prefix):
        return False
    identifier = value[len(prefix) :]
    if len(identifier) != (32 if prefix else 36):
        return False
    try:
        parsed = UUID(identifier)
    except ValueError:
        return False
    canonical = parsed.hex if prefix else str(parsed)
    return parsed.version == 4 and identifier == canonical


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

    model = _response_model(method, resource, mental_model_id)
    if model is None:
        raise ValueError("unsupported OpenClaw response contract")

    try:
        model.model_validate(value)
    except ValidationError as exc:
        raise ValueError("invalid Hindsight OpenClaw response") from exc


def _response_model(
    method: str, resource: str, mental_model_id: str | None
) -> type[_Response] | None:
    if resource == "mental-models":
        if mental_model_id is not None and method in {"GET", "PATCH"}:
            return MentalModelResponse
        if mental_model_id is None:
            mental_models: dict[str, type[_Response]] = {
                "GET": MentalModelListResponse,
                "POST": CreateMentalModelResponse,
            }
            return mental_models.get(method)
    models: dict[tuple[str, str], type[_Response]] = {
        ("PUT", ""): BankProfileResponse,
        ("PATCH", "config"): BankConfigResponse,
        ("POST", "reflect"): ReflectResponse,
    }
    return models.get((method, resource))
