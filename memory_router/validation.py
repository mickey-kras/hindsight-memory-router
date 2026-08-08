from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from .errors import HttpError
from .models import RecallBody, RetainBody


def parse_retain_body(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _invalid_retain("retain body must be an object")
    try:
        parsed = RetainBody.model_validate(value)
    except ValidationError as exc:
        issue = exc.errors()[0] if exc.errors() else {}
        loc = issue.get("loc", ())
        if loc and loc[0] == "items":
            if len(loc) == 1:
                message = "retain body requires at least one memory item"
            elif len(loc) == 2:
                message = f"memory item {loc[1]} must be an object"
            else:
                field = loc[2]
                mapping = {
                    "content": f"memory item {loc[1]} content must be a non-empty string",
                    "context": "context must be a string or null",
                    "document_id": "document_id must be a string or null",
                    "timestamp": "timestamp must be a string or null",
                    "tags": "tags must contain strings",
                    "metadata": "metadata must map strings to strings",
                    "update_mode": "update_mode must be replace or append",
                }
                message = mapping.get(field, "retain body is invalid")
        elif loc and loc[0] == "async":
            message = "async must be a boolean"
        elif loc and loc[0] == "document_tags":
            message = "document_tags must contain strings"
        else:
            message = "retain body is invalid"
        raise _invalid_retain(message) from exc
    return parsed.model_dump(by_alias=True, exclude_none=True)


def parse_recall_body(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _invalid_recall("recall body must be an object")
    try:
        parsed = RecallBody.model_validate(value)
    except ValidationError as exc:
        issue = exc.errors()[0] if exc.errors() else {}
        field = (issue.get("loc") or (None,))[0]
        mapping = {
            "query": "recall query must be a non-empty string",
            "max_tokens": "max_tokens must be a positive integer",
            "budget": "budget must be low, mid, or high",
            "types": "types must contain strings",
            "tags": "tags must contain strings",
            "tags_match": "tags_match must be a string",
            "trace": "trace must be a boolean",
        }
        raise _invalid_recall(mapping.get(field, "recall body is invalid")) from exc
    return parsed.model_dump(by_alias=True, exclude_none=True)


def _invalid_retain(message: str) -> HttpError:
    return HttpError(400, "invalid_retain_body", message)


def _invalid_recall(message: str) -> HttpError:
    return HttpError(400, "invalid_recall_body", message)
