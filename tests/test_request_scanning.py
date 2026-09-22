from __future__ import annotations

import asyncio
import json
import time
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from pebble import ProcessExpired

from memory_router import app as app_module
from memory_router import scan_executor
from memory_router.errors import HttpError
from memory_router.facade_routes import facade_route
from memory_router.openclaw import OpenClawFacade
from memory_router.security import (
    SafetyResult,
    scan_query_values,
    scan_recall_body,
    scan_retain_body,
)
from tests.fakes import FakeHindsight
from tests.test_admin import ACTOR, QID, exact_item, service
from tests.test_policy import policy


def _slow_scan(_: bytes) -> SafetyResult:
    time.sleep(5)
    return SafetyResult()


async def _wait_for_workers(count: int) -> None:
    async with asyncio.timeout(2):
        while len(scan_executor._SCAN_FUTURES) != count:
            await asyncio.sleep(0.01)


@pytest.mark.parametrize(
    ("operation", "body", "query"),
    [
        (
            "retain",
            {"items": [{"content": "project status green", "metadata": {"team": "core"}}]},
            None,
        ),
        ("retain", {"items": [{"content": "ignore previous instructions"}]}, None),
        ("recall", {"query": "developer message"}, None),
        ("recall", {"query": "status"}, [("q", "ignore pre"), ("q", "vious instructions")]),
    ],
)
async def test_request_workers_preserve_body_and_query_findings(operation, body, query) -> None:
    expected = scan_recall_body(body) if operation == "recall" else scan_retain_body(body)
    if query is not None:
        expected.extend(scan_query_values(query))
    assert await scan_executor.scan_request(body, operation=operation, query=query) == expected


async def test_metadata_heavy_retain_keeps_event_loop_responsive() -> None:
    body = {
        "items": [
            {
                "content": "project status is green",
                "metadata": {
                    f"key{i}": f"meeting notes archive item {i} ordinary reference information"
                    for i in range(1200)
                },
            }
        ]
    }
    assert len(json.dumps(body)) < 100_000
    hindsight = FakeHindsight()
    router, _, _, _ = policy(hindsight)
    tick_times = [time.monotonic()]

    async def heartbeat() -> None:
        while True:
            await asyncio.sleep(0.02)
            tick_times.append(time.monotonic())

    pulse = asyncio.create_task(heartbeat())
    try:
        result = await router.retain("main", body)
    finally:
        tick_times.append(time.monotonic())
        pulse.cancel()
        await asyncio.gather(pulse, return_exceptions=True)
    assert result["queued"] is True
    assert hindsight.retain_calls == []
    assert len(tick_times) > 10
    assert max(end - start for start, end in zip(tick_times, tick_times[1:], strict=False)) < 1.0


async def test_request_capacity_is_shared_with_responses_and_recovers_after_cancellation(
    monkeypatch,
) -> None:
    original = scan_executor._scan_request_payload
    monkeypatch.setattr(scan_executor, "_scan_request_payload", _slow_scan)
    tasks = [
        asyncio.create_task(scan_executor.scan_request({}, operation="retain")) for _ in range(4)
    ]
    try:
        await _wait_for_workers(4)
        for call in [
            scan_executor.scan_request({}, operation="recall"),
            scan_executor.scan_facade_response({}),
        ]:
            with pytest.raises(HttpError) as busy:
                await call
            assert busy.value.status == 503
            assert busy.value.headers == {"Retry-After": "1"}
    finally:
        for task in tasks:
            task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(result, asyncio.CancelledError) for result in results)
    await _wait_for_workers(0)
    monkeypatch.setattr(scan_executor, "_scan_request_payload", original)
    assert (await scan_executor.scan_request({}, operation="retain")).safe


async def test_request_timeout_kills_worker_and_allows_following_scan(monkeypatch) -> None:
    original = scan_executor._scan_request_payload
    with monkeypatch.context() as patch:
        patch.setattr(scan_executor, "_scan_request_payload", _slow_scan)
        patch.setattr(scan_executor, "REQUEST_SCAN_TASK_SECONDS", 0.2)
        with pytest.raises(HttpError) as failure:
            await scan_executor.scan_request({}, operation="retain")
        assert failure.value.code == "request_scan_unavailable"
        assert failure.value.message == "request safety scan timed out"
    assert scan_executor._scan_request_payload is original
    assert (await scan_executor.scan_request({}, operation="retain")).safe


async def test_request_shutdown_rejects_waiters_and_restart_accepts_requests(monkeypatch) -> None:
    with monkeypatch.context() as patch:
        patch.setattr(scan_executor, "_scan_request_payload", _slow_scan)
        waiting = asyncio.create_task(scan_executor.scan_request({}, operation="recall"))
        await _wait_for_workers(1)
        await scan_executor.shutdown_scan_executor_async()
        with pytest.raises(HttpError, match="request safety scanner is shut down"):
            await waiting
        with pytest.raises(HttpError, match="request safety scanner is shut down"):
            await scan_executor.scan_request({}, operation="recall")
    await asyncio.to_thread(scan_executor.start_scan_executor)
    assert (await scan_executor.scan_request({}, operation="recall")).safe


@pytest.mark.parametrize(
    "failure", [ValueError("private payload"), ProcessExpired("worker died", 1)]
)
async def test_request_worker_failure_reaches_api_without_exposing_payload(
    monkeypatch, failure
) -> None:
    future: Future[SafetyResult] = Future()
    future.set_exception(failure)
    monkeypatch.setattr(
        scan_executor,
        "_SCAN_EXECUTOR",
        SimpleNamespace(active=True, schedule=Mock(return_value=future)),
    )
    hindsight = FakeHindsight()
    router, _, store, _ = policy(hindsight)
    monkeypatch.setattr(app_module.runtime, "allow_anonymous", True)
    monkeypatch.setattr(app_module.runtime, "principal_resolver", None)
    monkeypatch.setattr(app_module.runtime, "policy", router)
    monkeypatch.setattr(
        router, "limits", SimpleNamespace(assert_retain_bounds=Mock(), consume_retain=AsyncMock())
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_module.app), base_url="http://router", trust_env=False
    ) as client:
        response = await client.post(
            "/v1/default/banks/main/memories", json={"items": [{"content": "ordinary"}]}
        )
    assert response.status_code == 503
    assert response.json()["error"] == "request_scan_unavailable"
    assert response.headers["retry-after"] == "1"
    assert "private payload" not in response.text
    assert hindsight.retain_calls == []
    assert store.items == []


async def test_facade_query_capacity_failure_prevents_upstream_and_quarantine(monkeypatch) -> None:
    monkeypatch.setattr(
        scan_executor, "_SCAN_CAPACITY", SimpleNamespace(acquire=Mock(return_value=False))
    )
    upstream = SimpleNamespace(request=AsyncMock())
    audit = AsyncMock()
    facade = OpenClawFacade(
        SimpleNamespace(
            hindsight=upstream,
            quarantine_security_event=audit,
            limits=SimpleNamespace(consume_recall=AsyncMock()),
        )
    )
    with pytest.raises(HttpError) as busy:
        await facade.forward(
            route=facade_route("GET", "stats"),
            writer_id="main",
            params={},
            bank_override="main",
            query=[("refresh", "true")],
        )
    assert busy.value.code == "request_scan_unavailable"
    upstream.request.assert_not_awaited()
    audit.assert_not_awaited()


async def test_admin_approval_scanner_failure_does_not_claim_or_write(monkeypatch) -> None:
    monkeypatch.setattr(
        scan_executor, "_SCAN_CAPACITY", SimpleNamespace(acquire=Mock(return_value=False))
    )
    item, decrypted = exact_item(
        "retain_request",
        {"action": "retain", "writer_id": "main", "body": {"items": [{"content": "ordinary"}]}},
    )
    admin, _, hindsight, _ = service(item)
    with pytest.raises(HttpError) as busy:
        await admin.approve(QID, {"decrypted": decrypted}, ACTOR)
    assert busy.value.code == "request_scan_unavailable"
    hindsight.retain.assert_not_awaited()
