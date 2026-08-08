from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from .errors import HttpError
from .models import RecallBody, RetainBody


def parse_retain_body(value: Any) -> RetainBody:
    if not isinstance(value, dict):
        raise _retain("retain body must be an object")
    items = value.get("items")
    if not isinstance(items, list) or not items:
        raise _retain("retain body requires at least one memory item")
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise _retain(f"memory item {index} must be an object")
        content = item.get("content")
        if not isinstance(content, str) or not content.strip():
            raise _retain(f"memory item {index} content must be a non-empty string")
        if "context" in item and item["context"] is not None and not isinstance(item["context"], str):
            raise _retain("context must be a string or null")
        if "document_id" in item and item["document_id"] is not None and not isinstance(item["document_id"], str):
            raise _retain("document_id must be a string or null")
        if "timestamp" in item and item["timestamp"] is not None and not isinstance(item["timestamp"], str):
            raise _retain("timestamp must be a string or null")
        if "tags" in item and item["tags"] is not None and (
            not isinstance(item["tags"], list) or any(not isinstance(x, str) for x in item["tags"])
        ):
            raise _retain("tags must contain strings")
        if "metadata" in item and item["metadata"] is not None and (
            not isinstance(item["metadata"], dict)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in item["metadata"].items())
        ):
            raise _retain("metadata must map strings to strings")
        if "update_mode" in item and item["update_mode"] not in {None, "replace", "append"}:
            raise _retain("update_mode must be replace or append")
    if "async" in value and not isinstance(value["async"], bool):
        raise _retain("async must be a boolean")
    if "document_tags" in value and (
        not isinstance(value["document_tags"], list)
        or any(not isinstance(x, str) for x in value["document_tags"])
    ):
        raise _retain("document_tags must contain strings")
    try:
        return RetainBody.model_validate(value)
    except ValidationError as exc:
        raise _retain("retain body is invalid") from exc


def parse_recall_body(value: Any) -> RecallBody:
    if not isinstance(value, dict):
        raise _recall("recall body must be an object")
    query = value.get("query")
    if not isinstance(query, str) or not query.strip():
        raise _recall("recall query must be a non-empty string")
    if "max_tokens" in value:
        token = value["max_tokens"]
        if isinstance(token, bool) or not isinstance(token, int) or token <= 0:
            raise _recall("max_tokens must be a positive integer")
    if "budget" in value and value["budget"] not in {"low", "mid", "high"}:
        raise _recall("budget must be low, mid, or high")
    for field in ("types", "tags"):
        if field in value and value[field] is not None and (
            not isinstance(value[field], list) or any(not isinstance(x, str) for x in value[field])
        ):
            raise _recall(f"{field} must contain strings")
    if "tags_match" in value and not isinstance(value["tags_match"], str):
        raise _recall("tags_match must be a string")
    if "trace" in value and not isinstance(value["trace"], bool):
        raise _recall("trace must be a boolean")
    try:
        return RecallBody.model_validate(value)
    except ValidationError as exc:
        raise _recall("recall body is invalid") from exc


def _retain(message: str) -> HttpError:
    return HttpError(400, "invalid_retain_body", message)


def _recall(message: str) -> HttpError:
    return HttpError(400, "invalid_recall_body", message)
