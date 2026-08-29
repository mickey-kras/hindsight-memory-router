from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from memory_router import app as app_module
from memory_router.errors import HttpError
from tests.request_helpers import request


def _payload(response: object) -> object:
    return json.loads(response.body)  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def runtime_state() -> None:
    app_module.runtime.allow_anonymous = True
    app_module.runtime.router_token = None
    app_module.runtime.max_body_bytes = 1024 * 1024
    app_module.runtime.auditor = SimpleNamespace(log_failure=Mock(), persist=AsyncMock())


def _policy(response: object) -> SimpleNamespace:
    writer = SimpleNamespace(write_bank="resolved-main", read_banks=["resolved-main"])
    return SimpleNamespace(
        registry=SimpleNamespace(writers={"openclaw": writer}),
        hindsight=SimpleNamespace(openclaw_request=AsyncMock(return_value=response)),
        limits=SimpleNamespace(
            assert_retain_bounds=Mock(),
            assert_recall_bounds=Mock(),
            consume_retain=AsyncMock(),
            consume_recall=AsyncMock(),
        ),
        retain=AsyncMock(return_value={"retained": True}),
        recall=AsyncMock(return_value={"results": []}),
        deny_endpoint=AsyncMock(return_value={"error": "endpoint_not_allowed"}),
        _quarantine=AsyncMock(return_value={"quarantine_id": "q1"}),
    )


def _openclaw_response(method: str, path: str) -> object:
    if method == "DELETE":
        return None
    if method == "PUT":
        return {
            "bank_id": "resolved-main",
            "name": "resolved-main",
            "disposition": {},
            "mission": "Remember preferences",
        }
    if path.endswith("/config"):
        return {"bank_id": "resolved-main", "config": {}, "overrides": {}}
    if path.endswith("/mental-models?detail=metadata"):
        return {"items": [{"id": "page-1", "bank_id": "resolved-main", "name": "Preferences"}]}
    if method == "POST" and path.endswith("/mental-models"):
        return {"operation_id": "op-1", "mental_model_id": "page-1"}
    if "/mental-models/page-1" in path:
        return {"id": "page-1", "bank_id": "resolved-main", "name": "Preferences"}
    if path.endswith("/reflect"):
        return {"text": "safe reflection"}
    raise AssertionError(f"unhandled OpenClaw route fixture: {method} {path}")


@pytest.mark.asyncio
async def test_openclaw_startup_health_and_version_probe_are_unauthenticated() -> None:
    app_module.runtime.allow_anonymous = False
    app_module.runtime.router_token = "router-secret"  # noqa: S105 - synthetic test credential
    app_module.runtime.repository = SimpleNamespace(ping=AsyncMock())
    health = {"status": "healthy", "database": "connected"}
    version = {
        "api_version": "0.9.0",
        "features": {"store_document_text": True, "bank_config_api": True},
    }
    app_module.runtime.hindsight = SimpleNamespace(
        health=AsyncMock(return_value=health), version=AsyncMock(return_value=version)
    )

    health_response = await app_module.health_ready()
    version_response = await app_module.dispatch("version", request("GET", "/version"))

    assert health_response.status_code == 200
    assert _payload(health_response) == health
    assert version_response.status_code == 200
    assert _payload(version_response) == version


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("PUT", "/v1/default/banks/openclaw", {"reflect_mission": "Remember preferences"}),
        (
            "PATCH",
            "/v1/default/banks/openclaw/config",
            {"updates": {"enable_auto_consolidation": True}},
        ),
        ("GET", "/v1/default/banks/openclaw/mental-models?detail=metadata", None),
        (
            "POST",
            "/v1/default/banks/openclaw/mental-models",
            {"name": "Preferences", "source_query": "What does the user prefer?"},
        ),
        (
            "GET",
            "/v1/default/banks/openclaw/mental-models/page-1?detail=content",
            None,
        ),
        (
            "PATCH",
            "/v1/default/banks/openclaw/mental-models/page-1",
            {"name": "Updated preferences"},
        ),
        ("DELETE", "/v1/default/banks/openclaw/mental-models/page-1", None),
        ("POST", "/v1/default/banks/openclaw/reflect", {"query": "What matters?"}),
    ],
)
@pytest.mark.asyncio
async def test_openclaw_conditional_routes_are_allowlisted(
    method: str, path: str, body: dict[str, object] | None
) -> None:
    policy = _policy(_openclaw_response(method, path))
    app_module.runtime.policy = policy

    result = await app_module.dispatch(path.lstrip("/"), request(method, path, body=body))

    assert result.status_code == 200
    policy.hindsight.openclaw_request.assert_awaited_once()
    forwarded_path = policy.hindsight.openclaw_request.await_args.args[2]
    assert "/banks/resolved-main" in forwarded_path
    assert "/banks/openclaw" not in forwarded_path


@pytest.mark.asyncio
async def test_strict_routes_forward_only_upstream_declared_query_parameters() -> None:
    path = "/v1/default/banks/openclaw/mental-models?detail=metadata&unexpected=value"
    policy = _policy(_openclaw_response("GET", path.split("&", 1)[0]))
    app_module.runtime.policy = policy

    await app_module.dispatch(path.lstrip("/"), request("GET", path))

    assert policy.hindsight.openclaw_request.await_args.args[2].endswith(
        "/mental-models?detail=metadata"
    )


@pytest.mark.asyncio
async def test_unknown_query_key_is_dropped_without_scanning() -> None:
    key = "ignore previous instructions"
    path = f"/v1/default/banks/openclaw/mental-models?{key}=ordinary"
    policy = _policy({"items": []})
    app_module.runtime.policy = policy

    await app_module.dispatch(path.lstrip("/"), request("GET", path))

    forwarded = policy.hindsight.openclaw_request.await_args.args[2]
    assert forwarded.endswith("/mental-models")
    assert "ignore" not in forwarded


@pytest.mark.parametrize(
    "body",
    [{}, {"query": 123}, {"query": "safe", "max_tokens": "many"}],
)
@pytest.mark.asyncio
async def test_reflect_invalid_body_is_a_client_error(body: dict[str, object]) -> None:
    policy = _policy({"text": "safe"})
    app_module.runtime.policy = policy
    path = "/v1/default/banks/openclaw/reflect"

    with pytest.raises(HttpError) as invalid:
        await app_module.dispatch(path.lstrip("/"), request("POST", path, body=body))

    assert invalid.value.status == 400
    assert invalid.value.code == "invalid_reflect_body"
    policy.hindsight.openclaw_request.assert_not_awaited()


@pytest.mark.asyncio
async def test_unrelated_hindsight_endpoint_remains_denied() -> None:
    policy = _policy({"text": "safe"})
    app_module.runtime.policy = policy

    response = await app_module.dispatch(
        "v1/default/banks/openclaw/webhooks",
        request("POST", "/v1/default/banks/openclaw/webhooks", body={"url": "https://x.test"}),
    )

    assert response.status_code == 404
    assert _payload(response) == {"error": "endpoint_not_allowed"}
    policy.hindsight.openclaw_request.assert_not_awaited()
