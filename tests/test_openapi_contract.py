from __future__ import annotations

import json
import pathlib

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
EXPECTED_ROUTES = {
    "/health": {"get"},
    "/health/live": {"get"},
    "/health/ready": {"get"},
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


def _facade_routes() -> dict[str, set[str]]:
    from memory_router.facade_routes import FACADE_ROUTES

    routes: dict[str, set[str]] = {}
    for route in FACADE_ROUTES:
        path = "/v1/default/banks/{bank_id}"
        if route.template:
            path += "/" + route.template
        routes.setdefault(path, set()).add(route.method.lower())
    return routes


OPENCLAW_ROUTES = _facade_routes()


def _spec() -> dict[str, object]:
    return json.loads(pathlib.Path("openapi/openapi.json").read_text())


def _openclaw_spec() -> dict[str, object]:
    return json.loads(pathlib.Path("openapi/openclaw.json").read_text())


def _methods(spec: dict[str, object]) -> dict[str, set[str]]:
    paths = spec["paths"]
    assert isinstance(paths, dict)
    return {
        path: set(value) & HTTP_METHODS for path, value in paths.items() if isinstance(value, dict)
    }


def test_openapi_paths_and_methods_match_composed_router_surface() -> None:
    assert _methods(_spec()) == EXPECTED_ROUTES
    assert _methods(_openclaw_spec()) == OPENCLAW_ROUTES


def test_openapi_surface_is_backed_by_dispatch_handlers() -> None:
    source = pathlib.Path("memory_router/app.py").read_text()
    markers = {
        "/health": '@app.get("/health")',
        "/health/live": '@app.get("/health/live")',
        "/health/ready": '@app.get("/health/ready")',
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

    assert "match_facade_route(method, pathname)" in source


def test_version_and_recall_openapi_match_hindsight_facade() -> None:
    spec = _spec()
    paths = spec["paths"]
    assert isinstance(paths, dict)
    version = paths["/version"]["get"]
    assert "503" in version["responses"]
    assert version["security"] == []
    assert "401" not in version["responses"]
    assert {"200", "4XX", "502", "503", "504"} <= set(version["responses"])

    schemas = spec["components"]["schemas"]
    version_schema = schemas["VersionResponse"]
    assert version_schema["required"] == ["api_version", "features"]
    assert set(version_schema["properties"]) == {"api_version", "features"}

    recall_schema = schemas["RecallResponse"]
    assert set(recall_schema["properties"]) == {
        "results",
        "chunks",
        "entities",
        "source_facts",
        "trace",
    }


def test_openclaw_openapi_success_statuses_match_dispatch() -> None:
    from memory_router.facade_routes import FACADE_ROUTES

    paths = _openclaw_spec()["paths"]
    assert isinstance(paths, dict)
    for route in FACADE_ROUTES:
        path = "/v1/default/banks/{bank_id}"
        if route.template:
            path += "/" + route.template
        responses = paths[path][route.method.lower()]["responses"]
        assert str(route.success_status) in responses


def test_openclaw_openapi_documents_auth_blocking_and_upstream_statuses() -> None:
    spec = _openclaw_spec()
    paths = spec["paths"]
    assert isinstance(paths, dict)
    for path_item in paths.values():
        assert isinstance(path_item, dict)
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            assert operation["security"] == [{"RouterToken": []}]
            responses = operation["responses"]
            assert {"400", "401", "404", "422", "429", "4XX", "502", "504"} <= set(responses)
            assert ("413" in responses) is ("requestBody" in operation)


def test_openclaw_openapi_documents_route_metadata_and_response_schemas() -> None:
    from memory_router.facade_routes import FACADE_ROUTES

    paths = _openclaw_spec()["paths"]
    assert isinstance(paths, dict)
    for route in FACADE_ROUTES:
        path = "/v1/default/banks/{bank_id}"
        if route.template:
            path += "/" + route.template
        operation = paths[path][route.method.lower()]
        query = {
            parameter["name"]: parameter.get("required") is True
            for parameter in operation.get("parameters", [])
            if parameter.get("in") == "query"
        }
        assert query == {name: name in route.required_query_params for name in route.query_params}
        request_body = operation.get("requestBody")
        if route.body == "none":
            assert request_body is None
        else:
            assert request_body["required"] is (route.body == "required")
        success = operation["responses"][str(route.success_status)]
        assert "schema" in success["content"]["application/json"]

    assert paths["/v1/default/banks/{bank_id}/audit-logs/stats"]["get"]["operationId"] == (
        "hindsightGetAuditLogsStats"
    )
    rate_limited = _openclaw_spec()["components"]["responses"]["RateLimited"]
    assert "Retry-After" in rate_limited["headers"]


def test_openclaw_strict_contracts_have_exact_openapi_schemas() -> None:
    spec = _openclaw_spec()
    paths = spec["paths"]
    expected = {
        ("/v1/default/banks/{bank_id}", "put"): "BankProfileResponse",
        ("/v1/default/banks/{bank_id}/config", "patch"): "BankConfigResponse",
        ("/v1/default/banks/{bank_id}/mental-models", "get"): "MentalModelListResponse",
        ("/v1/default/banks/{bank_id}/mental-models", "post"): "CreateMentalModelResponse",
        (
            "/v1/default/banks/{bank_id}/mental-models/{mental_model_id}",
            "get",
        ): "MentalModelResponse",
        (
            "/v1/default/banks/{bank_id}/mental-models/{mental_model_id}",
            "patch",
        ): "MentalModelResponse",
        ("/v1/default/banks/{bank_id}/reflect", "post"): "ReflectResponse",
    }
    for (path, method), schema_name in expected.items():
        schema = paths[path][method]["responses"]["200"]["content"]["application/json"]["schema"]
        assert schema == {"$ref": f"#/components/schemas/{schema_name}"}

    schemas = spec["components"]["schemas"]
    assert schemas["BankProfileResponse"]["required"] == [
        "bank_id",
        "name",
        "disposition",
        "mission",
    ]
    assert schemas["BankConfigResponse"]["required"] == ["bank_id", "config", "overrides"]
    assert schemas["MentalModelResponse"]["required"] == ["id", "bank_id", "name"]
    assert schemas["MentalModelListResponse"]["required"] == ["items"]
    assert schemas["CreateMentalModelResponse"]["required"] == ["operation_id"]
    assert schemas["ReflectResponse"]["required"] == ["text"]

    reflect = paths["/v1/default/banks/{bank_id}/reflect"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert reflect["properties"]["query"] == {
        "type": "string",
        "minLength": 1,
        "pattern": r"\S",
    }
    assert set(reflect["properties"]) == {
        "query",
        "max_tokens",
        "budget",
        "types",
        "tags",
        "tags_match",
        "trace",
    }
