from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
MIN_FACADE_OPERATION_COUNT = 75


def _methods(source: str, receivers: tuple[str, ...]) -> set[str]:
    joined = "|".join(re.escape(receiver) for receiver in receivers)
    return set(re.findall(rf"(?:{joined})\.([A-Za-z][A-Za-z0-9_]*)\s*\(", source))


def _git_blob_sha(source: str) -> str:
    data = source.encode()
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _upstream_operations(source: str, *, minimum: int = 1) -> dict[tuple[str, str], dict[str, Any]]:
    document = yaml.safe_load(source)
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("upstream OpenAPI document has no paths object")
    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    for path, path_item in document["paths"].items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        shared_parameters = path_item.get("parameters", [])
        if not isinstance(shared_parameters, list):
            shared_parameters = []
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            request_body = operation.get("requestBody")
            if request_body is None:
                body_mode = "none"
            elif isinstance(request_body, dict) and request_body.get("required") is True:
                body_mode = "required"
            else:
                body_mode = "optional"
            parameters = [*shared_parameters]
            operation_parameters = operation.get("parameters", [])
            if isinstance(operation_parameters, list):
                parameters.extend(operation_parameters)
            query = {
                parameter["name"]: parameter.get("required") is True
                for parameter in parameters
                if isinstance(parameter, dict)
                and parameter.get("in") == "query"
                and isinstance(parameter.get("name"), str)
            }
            responses = operation.get("responses", {})
            statuses = set()
            if isinstance(responses, dict):
                statuses = {str(status).upper() for status in responses}
            endpoints[(method.upper(), path)] = {
                "body": body_mode,
                "deprecated": operation.get("deprecated") is True,
                "query": query,
                "statuses": statuses,
            }
    if len(endpoints) < minimum:
        raise ValueError(
            f"upstream OpenAPI parse yielded {len(endpoints)} operations; expected at least {minimum}"
        )
    return endpoints


def _supports_status(statuses: set[str], status: int) -> bool:
    return str(status) in statuses or f"{status // 100}XX" in statuses


def _documented_endpoints(path: Path) -> set[tuple[str, str]]:
    spec = json.loads(path.read_text(encoding="utf-8"))
    endpoints: set[tuple[str, str]] = set()
    for route, path_item in spec["paths"].items():
        normalized = route.replace("{writer_id}", "{bank_id}")
        for method in ("get", "post", "put", "patch", "delete"):
            if method in path_item:
                endpoints.add((method.upper(), normalized))
    return endpoints


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_openclaw_compat.py <hindsight-checkout>")

    root = Path(sys.argv[1])
    inventory = json.loads(Path("compat/openclaw.json").read_text(encoding="utf-8"))
    sources = {
        name: (root / path).read_text(encoding="utf-8")
        for name, path in inventory["sources"].items()
    }

    expected_blobs = inventory["source_blob_shas"]
    actual_blobs = {name: _git_blob_sha(source) for name, source in sources.items()}
    if actual_blobs != expected_blobs:
        changed = sorted(
            name for name, sha in actual_blobs.items() if expected_blobs.get(name) != sha
        )
        raise SystemExit(
            "Hindsight OpenClaw-facing upstream source changed; review endpoint/request/response "
            f"compatibility and refresh inventory: {changed}"
        )

    plugin = sources["plugin"]
    defaults = sources["bank_defaults"]
    sdk = sources["agent_sdk"]

    from memory_router.facade_routes import FACADE_ROUTES

    try:
        facade_operations = _upstream_operations(
            sources["facade_spec"], minimum=MIN_FACADE_OPERATION_COUNT
        )
    except (ValueError, yaml.YAMLError) as exc:
        raise SystemExit(f"could not parse upstream facade OpenAPI: {exc}") from exc
    missing_facade = []
    mismatched_statuses = []
    mismatched_bodies = []
    mismatched_queries = []
    deprecated_facade = []
    for route in FACADE_ROUTES:
        path = "/v1/default/banks/{bank_id}"
        if route.template:
            path += "/" + route.template
        operation = facade_operations.get((route.method, path))
        if operation is None:
            missing_facade.append((route.method, path))
            continue
        statuses = operation["statuses"]
        if not _supports_status(statuses, route.success_status):
            mismatched_statuses.append((route.method, path, route.success_status, sorted(statuses)))
        if operation["body"] != route.body:
            mismatched_bodies.append((route.method, path, route.body, operation["body"]))
        upstream_query = operation["query"]
        configured_query = {
            name: name in route.required_query_params for name in route.query_params
        }
        if upstream_query != configured_query:
            mismatched_queries.append((route.method, path, configured_query, upstream_query))
        if operation["deprecated"]:
            deprecated_facade.append((route.method, path))
    if missing_facade:
        raise SystemExit(f"facade routes missing upstream: {missing_facade}")
    if mismatched_statuses:
        raise SystemExit(f"facade success statuses differ from upstream: {mismatched_statuses}")
    if mismatched_bodies:
        raise SystemExit(f"facade body requiredness differs from upstream: {mismatched_bodies}")
    if mismatched_queries:
        raise SystemExit(f"facade query parameters differ from upstream: {mismatched_queries}")
    if deprecated_facade:
        raise SystemExit(f"deprecated upstream routes are exposed by facade: {deprecated_facade}")

    expected_plugin = set(inventory["plugin_client_methods"])
    actual_plugin = _methods(plugin, ("client", "c"))
    if actual_plugin != expected_plugin:
        raise SystemExit(
            f"OpenClaw Hindsight client surface changed: expected {sorted(expected_plugin)}, "
            f"found {sorted(actual_plugin)}"
        )

    expected_sdk = set(inventory["agent_sdk_methods"])
    actual_sdk = _methods(sdk, ("client", "sdk"))
    if actual_sdk != expected_sdk:
        raise SystemExit(
            f"OpenClaw agent SDK surface changed: expected {sorted(expected_sdk)}, "
            f"found {sorted(actual_sdk)}"
        )

    required_plugin_markers = ("/health", "/version")
    for marker in required_plugin_markers:
        if marker not in plugin:
            raise SystemExit(f"OpenClaw plugin no longer contains required probe {marker}")
    if "/config" not in defaults or 'method: "PATCH"' not in defaults:
        raise SystemExit("OpenClaw bank config PATCH call changed")

    expected_endpoints = {tuple(item) for item in inventory["endpoints"]}
    required_endpoints = {
        ("GET", "/health"),
        ("GET", "/version"),
        ("POST", "/v1/default/banks/{bank_id}/memories"),
        ("POST", "/v1/default/banks/{bank_id}/memories/recall"),
        ("PUT", "/v1/default/banks/{bank_id}"),
        ("PATCH", "/v1/default/banks/{bank_id}/config"),
        ("GET", "/v1/default/banks/{bank_id}/mental-models"),
        ("POST", "/v1/default/banks/{bank_id}/mental-models"),
        ("GET", "/v1/default/banks/{bank_id}/mental-models/{mental_model_id}"),
        ("PATCH", "/v1/default/banks/{bank_id}/mental-models/{mental_model_id}"),
        ("DELETE", "/v1/default/banks/{bank_id}/mental-models/{mental_model_id}"),
        ("POST", "/v1/default/banks/{bank_id}/reflect"),
    }
    if expected_endpoints != required_endpoints:
        raise SystemExit("compat/openclaw.json endpoint inventory changed without updating checker")

    documented = _documented_endpoints(Path("openapi/openapi.json")) | _documented_endpoints(
        Path("openapi/openclaw.json")
    )
    missing_docs = sorted(expected_endpoints - documented)
    if missing_docs:
        raise SystemExit(f"OpenClaw inventory endpoints missing from OpenAPI: {missing_docs}")

    compatibility_tests = (
        Path("tests/test_openclaw_compat.py").read_text(encoding="utf-8")
        + Path("tests/test_openclaw_routes.py").read_text(encoding="utf-8")
        + Path("tests/test_openclaw_provider_boundaries.py").read_text(encoding="utf-8")
        + Path("tests/integration/openclaw-compat.sh").read_text(encoding="utf-8")
    )
    required_coverage_markers = {
        "configured bank defaults",
        "auto-retain",
        "auto-recall",
        "knowledge-page list get create update delete",
        "knowledge reflect",
        "document ingest",
        "strings_keys_and_values_are_scanned",
        "each_openclaw_conditional_route_blocks_unsafe_provider_content",
    }
    missing_coverage = sorted(
        marker for marker in required_coverage_markers if marker not in compatibility_tests
    )
    if missing_coverage:
        raise SystemExit(f"OpenClaw compatibility coverage markers missing: {missing_coverage}")

    print("OpenClaw compatibility inventory matches current upstream call surface")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
