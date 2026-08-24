from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


def _methods(source: str, receivers: tuple[str, ...]) -> set[str]:
    joined = "|".join(re.escape(receiver) for receiver in receivers)
    return set(re.findall(rf"(?:{joined})\.([A-Za-z][A-Za-z0-9_]*)\s*\(", source))


def _git_blob_sha(source: str) -> str:
    data = source.encode()
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _upstream_success_statuses(source: str) -> dict[tuple[str, str], set[int]]:
    endpoints: dict[tuple[str, str], set[int]] = {}
    path: str | None = None
    method: str | None = None
    in_responses = False
    for line in source.splitlines():
        if match := re.fullmatch(r"  (/[^:]+):", line):
            path = match.group(1)
            method = None
            in_responses = False
        elif match := re.fullmatch(r"    (get|post|put|patch|delete):", line):
            method = match.group(1).upper()
            in_responses = False
        elif line == "      responses:":
            in_responses = True
        elif in_responses and (match := re.fullmatch(r'        "(2\d\d)":', line)):
            if path is not None and method is not None:
                endpoints.setdefault((method, path), set()).add(int(match.group(1)))
    return endpoints


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

    facade_statuses = _upstream_success_statuses(sources["facade_spec"])
    missing_facade = []
    mismatched_statuses = []
    for route in FACADE_ROUTES:
        path = "/v1/default/banks/{bank_id}"
        if route.template:
            path += "/" + route.template
        statuses = facade_statuses.get((route.method, path))
        if statuses is None:
            missing_facade.append((route.method, path))
        elif route.success_status not in statuses:
            mismatched_statuses.append(
                (route.method, path, route.success_status, sorted(statuses))
            )
    if missing_facade:
        raise SystemExit(f"facade routes missing upstream: {missing_facade}")
    if mismatched_statuses:
        raise SystemExit(f"facade success statuses differ from upstream: {mismatched_statuses}")

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
    if "/config" not in defaults or "method: \"PATCH\"" not in defaults:
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
