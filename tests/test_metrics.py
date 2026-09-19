from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from memory_router.errors import HttpError
from memory_router.principals import PrincipalRegistry, PrincipalResolver
from tests.request_helpers import request

from memory_router import app as app_module
from memory_router import config, metrics
from memory_router.auth import AuthFailureAuditor
from memory_router.hindsight import HindsightGateway, HindsightGatewayError

_ADMIN_TOKENS = {
    "legacy": "legacy-token",
    "read": "read-token",
    "review": "review-token",
    "cleanup": "cleanup-token",
}
_OPERATOR_SECRET = "a" * 64
_VIEWER_SECRET = "b" * 64


def _principal_resolver() -> PrincipalResolver:
    registry = PrincipalRegistry.model_validate(
        {
            "principals": {
                "operator": {
                    "keys": [
                        {
                            "id": "op-key",
                            "sha256": hashlib.sha256(_OPERATOR_SECRET.encode()).hexdigest(),
                            "created_at": "2024-01-01T00:00:00+00:00",
                        }
                    ],
                    "grants": [{"bank": "main", "scopes": ["quarantine.review"]}],
                },
                "viewer": {
                    "keys": [
                        {
                            "id": "view-key",
                            "sha256": hashlib.sha256(_VIEWER_SECRET.encode()).hexdigest(),
                            "created_at": "2024-01-01T00:00:00+00:00",
                        }
                    ],
                    "grants": [{"bank": "main", "scopes": ["bank.list"]}],
                },
            }
        }
    )
    return PrincipalResolver(registry)


@pytest.fixture(autouse=True)
def metrics_state() -> None:
    metrics.reset()
    app_module.runtime.metrics_enabled = True
    app_module.runtime.allow_anonymous = False
    app_module.runtime.router_token = "router-token"  # noqa: S105 - synthetic test credential
    app_module.runtime.principal_resolver = None
    app_module.runtime.admin_tokens = dict(_ADMIN_TOKENS)
    app_module.runtime.admin_read_max = 120
    app_module.runtime.admin_write_max = 30
    app_module.runtime.admin_window = 60_000
    app_module.runtime.admin_limiter = SimpleNamespace(consume_many=AsyncMock())
    app_module.runtime.auth_limiter = SimpleNamespace(consume_many=AsyncMock())
    app_module.runtime.auth_prefilter = app_module.InMemoryRateLimiter()
    app_module.runtime.auth_failure_max = 120
    app_module.runtime.auth_failure_window = 60_000
    app_module.runtime.auditor = AuthFailureAuditor(SimpleNamespace(put=AsyncMock()))
    app_module.runtime.repository = SimpleNamespace(
        stats=AsyncMock(return_value={"review_side_effect_started_items": 3})
    )


@pytest.mark.asyncio
async def test_metrics_endpoint_serves_prometheus_text_to_admin_read_scope() -> None:
    body = (
        await app_module.dispatch(
            "metrics",
            request("GET", "/metrics", headers={"authorization": "Bearer read-token"}),
        )
    ).body.decode()
    for token in ("read-token", "review-token", "legacy-token"):
        response = await app_module.dispatch(
            "metrics", request("GET", "/metrics", headers={"authorization": f"Bearer {token}"})
        )
        assert response.status_code == 200, token
        assert response.headers["content-type"] == metrics.CONTENT_TYPE
    assert "# TYPE memory_router_auth_failures_total counter" in body
    assert "# TYPE memory_router_review_side_effect_started_items gauge" in body
    assert "memory_router_review_side_effect_started_items 3" in body


@pytest.mark.asyncio
async def test_metrics_endpoint_rejects_anonymous_and_wrong_scope_tokens() -> None:
    for headers in (
        {},
        {"authorization": "Bearer cleanup-token"},
        {"authorization": "Bearer nope"},
    ):
        response = await app_module.dispatch("metrics", request("GET", "/metrics", headers=headers))
        assert response.status_code == 401, headers
    rendered = metrics.render()
    assert 'memory_router_auth_failures_total{route_class="metrics"} 3' in rendered

    response = await app_module.dispatch("metrics", request("POST", "/metrics"))
    assert response.status_code == 401
    assert 'memory_router_auth_failures_total{route_class="metrics"} 4' in metrics.render()


@pytest.mark.asyncio
async def test_metrics_endpoint_allows_principals_with_review_grants() -> None:
    app_module.runtime.principal_resolver = _principal_resolver()
    app_module.runtime.principal_limiter = SimpleNamespace(consume_many=AsyncMock())

    response = await app_module.dispatch(
        "metrics",
        request(
            "GET", "/metrics", headers={"authorization": f"Bearer mr_op-key_{_OPERATOR_SECRET}"}
        ),
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == metrics.CONTENT_TYPE

    with pytest.raises(HttpError) as excinfo:
        await app_module.dispatch(
            "metrics",
            request(
                "GET", "/metrics", headers={"authorization": f"Bearer mr_view-key_{_VIEWER_SECRET}"}
            ),
        )
    assert excinfo.value.status == 403
    assert excinfo.value.code == "authorization_denied"

    response = await app_module.dispatch(
        "metrics",
        request("GET", "/metrics", headers={"authorization": f"Bearer mr_op-key_{'c' * 64}"}),
    )
    assert response.status_code == 401
    assert 'memory_router_auth_failures_total{route_class="metrics"} 1' in metrics.render()


@pytest.mark.asyncio
async def test_metrics_endpoint_stays_closed_when_disabled() -> None:
    app_module.runtime.metrics_enabled = False
    app_module.runtime.allow_anonymous = True
    app_module.runtime.router_token = None
    policy = SimpleNamespace(
        deny_endpoint=AsyncMock(return_value={"error": "endpoint_not_allowed"})
    )
    app_module.runtime.policy = policy

    response = await app_module.dispatch("metrics", request("GET", "/metrics"))

    assert response.status_code == 404
    policy.deny_endpoint.assert_awaited_once_with("GET", "/metrics")


@pytest.mark.asyncio
async def test_error_responses_are_counted_by_route_class() -> None:
    limited = await app_module.http_error_handler(
        request("POST", "/v1/default/banks/main/memories"),
        HttpError(429, "quarantine_rate_limited", "slow down"),
    )
    assert limited.status_code == 429
    capacity = await app_module.http_error_handler(
        request("POST", "/v1/default/banks/main/memories"),
        HttpError(507, "quarantine_capacity_exceeded", "quarantine capacity is exhausted"),
    )
    assert capacity.status_code == 507
    other = await app_module.http_error_handler(
        request("GET", "/version"), HttpError(400, "invalid_request", "bad request")
    )
    assert other.status_code == 400

    rendered = metrics.render()
    assert 'memory_router_rate_limited_responses_total{route_class="memory"} 1' in rendered
    assert 'memory_router_quarantine_capacity_rejections_total{route_class="memory"} 1' in rendered
    assert not any(
        line.startswith('memory_router_rate_limited_responses_total{route_class="version"')
        for line in rendered.splitlines()
    )


@pytest.mark.asyncio
async def test_sweeper_failure_is_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    app_module.runtime.repository = SimpleNamespace()
    monkeypatch.setattr(
        app_module,
        "recover_interrupted",
        AsyncMock(side_effect=RuntimeError("sweep storage offline")),
    )
    sleeps = 0

    async def fake_sleep(_: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        await app_module.runtime._sweep_loop(3600, 0)
    assert "memory_router_sweeper_failures_total 1" in metrics.render()


@pytest.mark.asyncio
async def test_degraded_recall_bank_is_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    gateway = HindsightGateway("http://hindsight.test", None)
    monkeypatch.setattr(
        gateway,
        "_request",
        AsyncMock(side_effect=HindsightGatewayError("network", operation="recall", method="POST")),
    )
    with pytest.raises(HindsightGatewayError):
        await gateway.recall("main", {"query": "x"})
    await gateway.close()
    assert "memory_router_recall_degraded_banks_total 1" in metrics.render()


def test_render_escapes_labels_and_omits_unrecorded_series() -> None:
    metrics.record_auth_failure('od"d\nclass')
    metrics.record_auth_failure('od"d\nclass')

    rendered = metrics.render()
    assert rendered.endswith("\n")
    assert (
        "# HELP memory_router_auth_failures_total Authentication failures by route class."
        in rendered.splitlines()
    )
    assert 'memory_router_auth_failures_total{route_class="od\\"d\\nclass"} 2' in rendered
    assert not any(
        line.startswith("memory_router_sweeper_failures_total ") for line in rendered.splitlines()
    )


def test_metrics_enabled_setting_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEMORY_ROUTER_METRICS_ENABLED", "true")
    assert config.load_settings().memory_router_metrics_enabled is True
    monkeypatch.setenv("MEMORY_ROUTER_METRICS_ENABLED", "1")
    with pytest.raises(RuntimeError, match="true or false"):
        config.load_settings()
