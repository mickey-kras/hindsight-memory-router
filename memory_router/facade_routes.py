from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

BodyMode = Literal["none", "optional", "required"]
ResponseMode = Literal["object", "array"]
RequestScanMode = Literal["recall", "retain"]

_MENTAL_MODEL_PATH = "mental-models/{mental_model_id}"
_DOCUMENT_PATH = "documents/{document_id}"
_DIRECTIVE_PATH = "directives/{directive_id}"


@dataclass(frozen=True, slots=True)
class FacadeRoute:
    method: str
    template: str
    read: bool
    request_scan: RequestScanMode
    body: BodyMode
    strict_contract: bool
    success_status: int
    body_label: str
    resource: str
    operation: str
    params: tuple[str, ...]
    query_params: tuple[str, ...]
    required_query_params: tuple[str, ...]
    response: ResponseMode
    allow_empty_response: bool
    pattern: re.Pattern[str]


def _route(
    method: str,
    template: str,
    *,
    read: bool,
    body: BodyMode,
    request_scan: RequestScanMode | None = None,
    strict: bool = False,
    success_status: int = 200,
    body_label: str | None = None,
    query: tuple[str, ...] = (),
    required_query: tuple[str, ...] = (),
    response: ResponseMode = "object",
) -> FacadeRoute:
    if not set(required_query) <= set(query):
        raise ValueError("required query parameters must be forwardable")
    params = tuple(re.findall(r"\{(\w+)\}", template))
    resource = "/".join(
        segment
        for segment in template.split("/")
        if not (segment.startswith("{") and segment.endswith("}"))
    )
    suffix = re.escape(template)
    for name in params:
        suffix = suffix.replace(re.escape("{" + name + "}"), f"(?P<{name}>[^/]+)")
    if suffix:
        suffix = "/" + suffix
    pattern = re.compile(rf"/v1/default/banks/(?P<bank>[^/]+){suffix}")
    label = body_label if body_label is not None else (resource.replace("/", " ") or "bank")
    return FacadeRoute(
        method=method,
        template=template,
        read=read,
        request_scan=request_scan or ("recall" if read else "retain"),
        body=body,
        strict_contract=strict,
        success_status=success_status,
        body_label=label,
        resource=resource,
        operation=resource.replace("/", "_") or "bank",
        params=params,
        query_params=query,
        required_query_params=required_query,
        response=response,
        allow_empty_response=method == "DELETE" or (method == "POST" and body == "none"),
        pattern=pattern,
    )


# Bank-scoped Hindsight facade surface. Static segments must precede parametrized
# siblings: dispatch forwards the first full match.
FACADE_ROUTES: tuple[FacadeRoute, ...] = (
    # OpenClaw plugin contract; upstream responses validated against strict models.
    _route("PUT", "", read=False, body="required", strict=True, body_label="bank"),
    _route("PATCH", "config", read=False, body="required", strict=True, body_label="bank config"),
    _route(
        "GET",
        "mental-models",
        read=True,
        body="none",
        strict=True,
        query=("tags", "tags_match", "detail", "limit", "offset"),
    ),
    _route(
        "POST", "mental-models", read=False, body="required", strict=True, body_label="mental-model"
    ),
    _route(
        "GET",
        _MENTAL_MODEL_PATH,
        read=True,
        body="none",
        strict=True,
        query=("detail",),
    ),
    _route(
        "PATCH",
        _MENTAL_MODEL_PATH,
        read=False,
        body="required",
        strict=True,
        body_label="mental-model",
    ),
    _route("DELETE", _MENTAL_MODEL_PATH, read=False, body="none", strict=True),
    _route("POST", "reflect", read=True, body="required", strict=True, body_label="reflect"),
    # Bank management.
    _route("PATCH", "", read=False, body="required", body_label="bank"),
    _route("DELETE", "", read=False, body="none"),
    _route("GET", "config", read=True, body="none"),
    _route("DELETE", "config", read=False, body="none"),
    _route("GET", "stats", read=True, body="none", query=("refresh",)),
    _route(
        "GET",
        "stats/memories-timeseries",
        read=True,
        body="none",
        query=("period", "time_field"),
    ),
    _route("GET", "tags", read=True, body="none", query=("q", "source", "limit", "offset")),
    _route(
        "GET",
        "graph",
        read=True,
        body="none",
        query=("type", "limit", "q", "tags", "tags_match", "document_id", "chunk_id"),
    ),
    _route("POST", "consolidate", read=False, body="optional"),
    _route("POST", "consolidation/recover", read=False, body="none"),
    # Memories.
    _route(
        "GET",
        "memories/list",
        read=True,
        body="none",
        query=(
            "type",
            "q",
            "consolidation_state",
            "state",
            "document_id",
            "entity_id",
            "tags",
            "tags_match",
            "limit",
            "offset",
        ),
    ),
    _route("DELETE", "memories", read=False, body="none", query=("type",)),
    _route(
        "POST",
        "memories/dry-run-extract",
        read=True,
        body="required",
        request_scan="retain",
    ),
    _route("GET", "memories/{memory_id}", read=True, body="none"),
    _route("PATCH", "memories/{memory_id}", read=False, body="required"),
    _route("GET", "memories/{memory_id}/history", read=True, body="none", response="array"),
    _route("DELETE", "memories/{memory_id}/observations", read=False, body="none"),
    # Documents.
    _route(
        "GET",
        "documents",
        read=True,
        body="none",
        query=("q", "tags", "tags_match", "limit", "offset"),
    ),
    _route("GET", _DOCUMENT_PATH, read=True, body="none"),
    _route("PATCH", _DOCUMENT_PATH, read=False, body="required"),
    _route("DELETE", _DOCUMENT_PATH, read=False, body="none"),
    _route(
        "GET",
        "documents/{document_id}/chunks",
        read=True,
        body="none",
        query=("limit", "offset"),
    ),
    _route("POST", "documents/{document_id}/reprocess", read=False, body="none"),
    # Entities.
    _route("GET", "entities", read=True, body="none", query=("limit", "offset")),
    _route("GET", "entities/graph", read=True, body="none", query=("limit", "min_count")),
    _route("GET", "entities/{entity_id}", read=True, body="none"),
    # Mental model operations.
    _route("POST", "mental-models/{mental_model_id}/refresh", read=False, body="none"),
    _route("POST", "mental-models/{mental_model_id}/clear", read=False, body="none"),
    _route("POST", "mental-models/{mental_model_id}/dry-run-refresh", read=True, body="none"),
    _route(
        "GET",
        "mental-models/{mental_model_id}/history",
        read=True,
        body="none",
        response="array",
    ),
    # Directives.
    _route(
        "GET",
        "directives",
        read=True,
        body="none",
        query=("tags", "tags_match", "active_only", "limit", "offset"),
    ),
    _route("POST", "directives", read=False, body="required"),
    _route("GET", _DIRECTIVE_PATH, read=True, body="none"),
    _route("PATCH", _DIRECTIVE_PATH, read=False, body="required"),
    _route("DELETE", _DIRECTIVE_PATH, read=False, body="none"),
    # Observations.
    _route("GET", "observations/scopes", read=True, body="none", query=("limit", "offset")),
    _route("DELETE", "observations", read=False, body="none"),
    # Background operations.
    _route(
        "GET",
        "operations",
        read=True,
        body="none",
        query=("status", "type", "limit", "offset", "exclude_parents"),
    ),
    _route(
        "GET",
        "operations/{operation_id}",
        read=True,
        body="none",
        query=("include_payload",),
    ),
    _route("DELETE", "operations/{operation_id}", read=False, body="none"),
    _route("DELETE", "operations/{operation_id}/delete", read=False, body="none"),
    _route("POST", "operations/{operation_id}/retry", read=False, body="none"),
    # Knowledge base.
    _route(
        "GET",
        "knowledge-base/search",
        read=True,
        body="none",
        query=("q", "limit"),
        required_query=("q",),
    ),
    _route("GET", "knowledge-base/tree", read=True, body="none"),
    _route("POST", "knowledge-base/folders", read=False, body="required", success_status=201),
    _route("POST", "knowledge-base/pages", read=False, body="required", success_status=201),
    _route("GET", "knowledge-base/pages/{page_id}", read=True, body="none"),
    _route("PATCH", "knowledge-base/nodes/{node_id}", read=False, body="required"),
    _route("DELETE", "knowledge-base/nodes/{node_id}", read=False, body="none"),
    # Bank observability.
    _route(
        "GET",
        "audit-logs",
        read=True,
        body="none",
        query=("action", "transport", "start_date", "end_date", "limit", "offset"),
    ),
    _route("GET", "audit-logs/stats", read=True, body="none", query=("action", "period")),
    _route(
        "GET",
        "llm-requests",
        read=True,
        body="none",
        query=(
            "status",
            "operation",
            "scope",
            "provider",
            "trace_id",
            "document_id",
            "memory_id",
            "group",
            "start_date",
            "end_date",
            "limit",
            "offset",
        ),
    ),
    _route("GET", "llm-requests/stats", read=True, body="none", query=("operation", "period")),
)


def facade_route(method: str, template: str) -> FacadeRoute:
    for route in FACADE_ROUTES:
        if route.method == method and route.template == template:
            return route
    raise KeyError(f"no facade route for {method} {template!r}")


def match_facade_route(method: str, pathname: str) -> tuple[FacadeRoute, re.Match[str]] | None:
    for route in FACADE_ROUTES:
        if route.method != method:
            continue
        match = route.pattern.fullmatch(pathname)
        if match is not None:
            return route, match
    return None
