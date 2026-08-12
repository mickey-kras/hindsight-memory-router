from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from memory_router import app as app_module
from tests.request_helpers import request


def _payload(response: object) -> object:
    return json.loads(response.body)  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def runtime_state() -> None:
    app_module.runtime.allow_anonymous = True
    app_module.runtime.router_token = None
    app_module.runtime.max_body_bytes = 1024 * 1024
    app_module.runtime.auditor = SimpleNamespace(record=AsyncMock())


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


@pytest.mark.asyncio
async def test_openclaw_startup_health_and_version_probe_are_unauthenticated() -> None:
    app_module.runtime.allow_anonymous = False
    app_module.runtime.router_token = "router-secret"
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
    response = None if method == "DELETE" else {"content": "safe"}
    policy = _policy(response)
    app_module.runtime.policy = policy

    result = await app_module.dispatch(path.lstrip("/"), request(method, path, body=body))

    assert result.status_code == (204 if method == "DELETE" else 200)
    policy.hindsight.openclaw_request.assert_awaited_once()
    forwarded_path = policy.hindsight.openclaw_request.await_args.args[2]
    assert "/banks/resolved-main" in forwarded_path
    assert "/banks/openclaw" not in forwarded_path


@pytest.mark.asyncio
async def test_unrelated_hindsight_endpoint_remains_denied() -> None:
    policy = _policy({"content": "safe"})
    app_module.runtime.policy = policy

    response = await app_module.dispatch(
        "v1/default/banks/openclaw/memories/list",
        request("GET", "/v1/default/banks/openclaw/memories/list"),
    )

    assert response.status_code == 404
    assert _payload(response) == {"error": "endpoint_not_allowed"}
    policy.hindsight.openclaw_request.assert_not_awaited()
