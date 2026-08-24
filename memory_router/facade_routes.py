from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

BodyMode = Literal["none", "optional", "required"]


@dataclass(frozen=True, slots=True)
class FacadeRoute:
    method: str
    template: str
    read: bool
    body: BodyMode
    strict_contract: bool
    body_label: str
    resource: str
    operation: str
    params: tuple[str, ...]
    pattern: re.Pattern[str]


def _route(
    method: str,
    template: str,
    *,
    read: bool,
    body: BodyMode,
    strict: bool = False,
    body_label: str | None = None,
) -> FacadeRoute:
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
        body=body,
        strict_contract=strict,
        body_label=label,
        resource=resource,
        operation=resource.replace("/", "_") or "bank",
        params=params,
        pattern=pattern,
    )


# Bank-scoped Hindsight facade surface. Static segments must precede parametrized
# siblings: dispatch forwards the first full match.
FACADE_ROUTES: tuple[FacadeRoute, ...] = (
    # OpenClaw plugin contract; upstream responses validated against strict models.
    _route("PUT", "", read=False, body="required", strict=True, body_label="bank"),
    _route("PATCH", "config", read=False, body="required", strict=True, body_label="bank config"),
    _route("GET", "mental-models", read=True, body="none", strict=True),
    _route(
        "POST", "mental-models", read=False, body="required", strict=True, body_label="mental-model"
    ),
    _route("GET", "mental-models/{mental_model_id}", read=True, body="none", strict=True),
    _route(
        "PATCH",
        "mental-models/{mental_model_id}",
        read=False,
        body="required",
        strict=True,
        body_label="mental-model",
    ),
    _route("DELETE", "mental-models/{mental_model_id}", read=False, body="none", strict=True),
    _route("POST", "reflect", read=True, body="required", strict=True, body_label="reflect"),
    # Bank management.
    _route("PATCH", "", read=False, body="required", body_label="bank"),
    _route("DELETE", "", read=False, body="none"),
    _route("GET", "profile", read=True, body="none"),
    _route("PUT", "profile", read=False, body="required"),
    _route("GET", "config", read=True, body="none"),
    _route("DELETE", "config", read=False, body="none"),
    _route("GET", "stats", read=True, body="none"),
    _route("GET", "stats/memories-timeseries", read=True, body="none"),
    _route("GET", "tags", read=True, body="none"),
    _route("GET", "graph", read=True, body="none"),
    _route("POST", "consolidate", read=False, body="optional"),
    _route("POST", "consolidation/recover", read=False, body="none"),
    # Memories.
    _route("GET", "memories/list", read=True, body="none"),
    _route("DELETE", "memories", read=False, body="none"),
    _route("POST", "memories/dry-run-extract", read=True, body="required"),
    _route("GET", "memories/{memory_id}", read=True, body="none"),
    _route("PATCH", "memories/{memory_id}", read=False, body="required"),
    _route("GET", "memories/{memory_id}/history", read=True, body="none"),
    _route("DELETE", "memories/{memory_id}/observations", read=False, body="none"),
    # Documents.
    _route("GET", "documents", read=True, body="none"),
    _route("GET", "documents/{document_id}", read=True, body="none"),
    _route("PATCH", "documents/{document_id}", read=False, body="required"),
    _route("DELETE", "documents/{document_id}", read=False, body="none"),
    _route("GET", "documents/{document_id}/chunks", read=True, body="none"),
    _route("POST", "documents/{document_id}/reprocess", read=False, body="none"),
    # Entities.
    _route("GET", "entities", read=True, body="none"),
    _route("GET", "entities/graph", read=True, body="none"),
    _route("GET", "entities/{entity_id}", read=True, body="none"),
    # Mental model operations.
    _route("POST", "mental-models/{mental_model_id}/refresh", read=False, body="none"),
    _route("POST", "mental-models/{mental_model_id}/clear", read=False, body="none"),
    _route("POST", "mental-models/{mental_model_id}/dry-run-refresh", read=True, body="none"),
    _route("GET", "mental-models/{mental_model_id}/history", read=True, body="none"),
    # Directives.
    _route("GET", "directives", read=True, body="none"),
    _route("POST", "directives", read=False, body="required"),
    _route("GET", "directives/{directive_id}", read=True, body="none"),
    _route("PATCH", "directives/{directive_id}", read=False, body="required"),
    _route("DELETE", "directives/{directive_id}", read=False, body="none"),
    # Observations.
    _route("GET", "observations/scopes", read=True, body="none"),
    _route("DELETE", "observations", read=False, body="none"),
    # Background operations.
    _route("GET", "operations", read=True, body="none"),
    _route("GET", "operations/{operation_id}", read=True, body="none"),
    _route("DELETE", "operations/{operation_id}", read=False, body="none"),
    _route("DELETE", "operations/{operation_id}/delete", read=False, body="none"),
    _route("POST", "operations/{operation_id}/retry", read=False, body="none"),
    # Knowledge base.
    _route("GET", "knowledge-base/search", read=True, body="none"),
    _route("GET", "knowledge-base/tree", read=True, body="none"),
    _route("POST", "knowledge-base/folders", read=False, body="required"),
    _route("POST", "knowledge-base/pages", read=False, body="required"),
    _route("GET", "knowledge-base/pages/{page_id}", read=True, body="none"),
    _route("PATCH", "knowledge-base/nodes/{node_id}", read=False, body="required"),
    _route("DELETE", "knowledge-base/nodes/{node_id}", read=False, body="none"),
    # Bank observability.
    _route("GET", "audit-logs", read=True, body="none"),
    _route("GET", "audit-logs/stats", read=True, body="none"),
    _route("GET", "llm-requests", read=True, body="none"),
    _route("GET", "llm-requests/stats", read=True, body="none"),
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
