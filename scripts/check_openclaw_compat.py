from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from yaml.constructor import ConstructorError  # type: ignore[import-untyped]

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
MIN_FACADE_OPERATION_COUNT = 75


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    explicit_keys: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in explicit_keys
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        explicit_keys.add(key)
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _methods(source: str, receivers: tuple[str, ...]) -> set[str]:
    joined = "|".join(re.escape(receiver) for receiver in receivers)
    return set(re.findall(rf"(?:{joined})\.([A-Za-z][A-Za-z0-9_]*)\s*\(", source))


def _git_blob_sha(source: str) -> str:
    data = source.encode()
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _upstream_operations(source: str, *, minimum: int = 1) -> dict[tuple[str, str], dict[str, Any]]:
    # Construct the SafeLoader subclass directly so duplicate-key checks cannot be bypassed.
    loader = _UniqueKeyLoader(source)
    try:
        document = loader.get_single_data()
    finally:
        loader.dispose()
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("upstream OpenAPI document has no paths object")
    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    for path, path_item in document["paths"].items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            raise ValueError("upstream OpenAPI paths must map string paths to objects")
        if "$ref" in path_item:
            raise ValueError(f"unsupported path-item $ref at {path}")
        shared_parameters = path_item.get("parameters", [])
        if not isinstance(shared_parameters, list):
            raise ValueError(f"parameters must be an array at {path}")
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise ValueError(f"operation must be an object at {method.upper()} {path}")
            request_body = operation.get("requestBody")
            if request_body is not None and not isinstance(request_body, dict):
                raise ValueError(f"requestBody must be an object at {method.upper()} {path}")
            if isinstance(request_body, dict) and "$ref" in request_body:
                raise ValueError(f"unsupported requestBody $ref at {method.upper()} {path}")
            if (
                isinstance(request_body, dict)
                and "required" in request_body
                and not isinstance(request_body["required"], bool)
            ):
                raise ValueError(f"requestBody.required must be boolean at {method.upper()} {path}")
            if request_body is None:
                body_mode = "none"
            elif isinstance(request_body, dict) and request_body.get("required") is True:
                body_mode = "required"
            else:
                body_mode = "optional"
            operation_parameters = operation.get("parameters", [])
            if not isinstance(operation_parameters, list):
                raise ValueError(f"parameters must be an array at {method.upper()} {path}")
            parameters = [*shared_parameters, *operation_parameters]
            if any(isinstance(parameter, dict) and "$ref" in parameter for parameter in parameters):
                raise ValueError(f"unsupported parameter $ref at {method.upper()} {path}")
            query: dict[str, bool] = {}
            seen_parameters: set[tuple[str, str]] = set()
            seen_operation_parameters: set[tuple[str, str]] = set()
            for parameter_index, parameter in enumerate(parameters):
                if not isinstance(parameter, dict):
                    raise ValueError(f"parameter must be an object at {method.upper()} {path}")
                location = parameter.get("in")
                name = parameter.get("name")
                required = parameter.get("required", False)
                if not isinstance(location, str) or not isinstance(name, str):
                    raise ValueError(
                        f"parameter name/in must be strings at {method.upper()} {path}"
                    )
                if not isinstance(required, bool):
                    raise ValueError(
                        f"parameter.required must be boolean at {method.upper()} {path}"
                    )
                identity = (location, name)
                is_operation_parameter = parameter_index >= len(shared_parameters)
                if identity in seen_operation_parameters or (
                    identity in seen_parameters and not is_operation_parameter
                ):
                    raise ValueError(
                        f"duplicate parameter {location}:{name} at {method.upper()} {path}"
                    )
                seen_parameters.add(identity)
                if is_operation_parameter:
                    seen_operation_parameters.add(identity)
                if location == "query":
                    query[name] = required
            responses = operation.get("responses", {})
            if not isinstance(responses, dict):
                raise ValueError(f"responses must be an object at {method.upper()} {path}")
            statuses = {str(status).upper() for status in responses}
            deprecated = operation.get("deprecated", False)
            if not isinstance(deprecated, bool):
                raise ValueError(f"deprecated must be boolean at {method.upper()} {path}")
            endpoints[(method.upper(), path)] = {
                "body": body_mode,
                "deprecated": deprecated,
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


if __name__ == "__main__":
    raise SystemExit(main())
