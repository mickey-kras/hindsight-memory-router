from __future__ import annotations

import json
import pathlib

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
EXPECTED_ROUTES = {
    "/health": {"get"},
    "/ready": {"get"},
    "/version": {"get"},
    "/v1/default/banks/{writer_id}/memories": {"post"},
    "/v1/default/banks/{writer_id}/memories/recall": {"post"},
    "/admin/quarantine/queue": {"get"},
    "/admin/quarantine/stats": {"get"},
    "/admin/quarantine/cleanup": {"post"},
    "/admin/quarantine/items/{quarantine_id}": {"get"},
    "/admin/quarantine/items/{quarantine_id}/approve": {"post"},
    "/admin/quarantine/items/{quarantine_id}/reject": {"post"},
    "/admin/quarantine/items/{quarantine_id}/postpone": {"post"},
}


def _spec() -> dict[str, object]:
    return json.loads(pathlib.Path("openapi/openapi.json").read_text())


def test_openapi_paths_and_methods_match_router_surface() -> None:
    spec = _spec()
    paths = spec["paths"]
    assert isinstance(paths, dict)
    actual = {
        path: set(value) & HTTP_METHODS for path, value in paths.items() if isinstance(value, dict)
    }
    assert actual == EXPECTED_ROUTES


def test_openapi_surface_is_backed_by_dispatch_handlers() -> None:
    source = pathlib.Path("memory_router/app.py").read_text()
    markers = {
        "/health": '@app.get("/health")',
        "/ready": '@app.get("/ready")',
        "/version": 'pathname == "/version"',
        "/v1/default/banks/{writer_id}/memories": r"/v1/default/banks/([^/]+)/memories(?:/(recall))?",
        "/v1/default/banks/{writer_id}/memories/recall": 'action == "recall"',
        "/admin/quarantine/queue": 'pathname == "/admin/quarantine/queue"',
        "/admin/quarantine/stats": 'pathname == "/admin/quarantine/stats"',
        "/admin/quarantine/cleanup": 'pathname == "/admin/quarantine/cleanup"',
        "/admin/quarantine/items/{quarantine_id}": r"/admin/quarantine/items/([^/]+)(?:/(approve|reject|postpone))?",
        "/admin/quarantine/items/{quarantine_id}/approve": 'action == "approve"',
        "/admin/quarantine/items/{quarantine_id}/reject": 'action == "reject"',
        "/admin/quarantine/items/{quarantine_id}/postpone": 'action == "postpone"',
    }
    assert set(markers) == set(EXPECTED_ROUTES)
    for path, marker in markers.items():
        assert marker in source, f"OpenAPI path has no dispatcher marker: {path}"


def test_openapi_version_matches_runtime_version() -> None:
    spec = _spec()
    info = spec["info"]
    assert isinstance(info, dict)
    version = info["version"]
    assert isinstance(version, str)
    source = pathlib.Path("memory_router/app.py").read_text()
    assert f'"api_version": "{version}"' in source
