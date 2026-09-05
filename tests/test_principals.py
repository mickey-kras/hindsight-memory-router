from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from memory_router import app as app_module
from memory_router.config import RouterSettings, assert_auth_environment
from memory_router.errors import HttpError
from memory_router.facade_routes import FACADE_ROUTES
from memory_router.logging_contract import sanitize_fields
from memory_router.principals import (
    SCOPE_VOCABULARY,
    PrincipalResolver,
    facade_scope,
    load_principal_registry,
)
from memory_router.rate_limit import ConcurrencyLeaseLost
from tests.request_helpers import request

ALPHA_SECRET = "a" * 64
READER_SECRET = "b" * 64
OLD_ALPHA_SECRET = "c" * 64
CREATED = "2026-09-01T00:00:00Z"


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _key(key_id: str, secret: str, **lifecycle: str) -> dict[str, str]:
    return {"id": key_id, "sha256": _digest(secret), "created_at": CREATED, **lifecycle}


def _registry_value() -> dict[str, object]:
    return {
        "principals": {
            "agent-alpha": {
                "keys": [
                    _key("alpha-old", OLD_ALPHA_SECRET),
                    _key("alpha-1", ALPHA_SECRET),
                ],
                "grants": [
                    {
                        "bank": "shared",
                        "scopes": ["bank.list", "memory.retain", "memory.recall"],
                    },
                    {"bank": "alpha-only", "scopes": ["bank.list"]},
                ],
            },
            "agent-reader": {
                "keys": [_key("reader-1", READER_SECRET)],
                "grants": [{"bank": "shared", "scopes": ["memory.recall"]}],
            },
        }
    }


def _write_registry(tmp_path: Path, value: object | None = None) -> str:
    path = tmp_path / "principals.json"
    path.write_text(json.dumps(value if value is not None else _registry_value()))
    return str(path)


def _resolver(tmp_path: Path) -> PrincipalResolver:
    return PrincipalResolver(load_principal_registry(_write_registry(tmp_path)))


def _bearer(key_id: str, secret: str) -> str:
    return f"Bearer mr_{key_id}_{secret}"


@pytest.fixture(autouse=True)
def principal_runtime_state(tmp_path: Path) -> None:
    app_module.runtime.principal_resolver = _resolver(tmp_path)
    app_module.runtime.allow_anonymous = False
    app_module.runtime.router_token = None
    app_module.runtime.max_body_bytes = 1024 * 1024
    app_module.runtime.auditor = SimpleNamespace(log_failure=Mock(), persist=AsyncMock())
    app_module.runtime.auth_limiter = SimpleNamespace(consume_many=AsyncMock())
    app_module.runtime.principal_limiter = SimpleNamespace(consume_many=AsyncMock())
    app_module.runtime.principal_concurrency_limiter = None
    app_module.runtime.principal_concurrency = {}
    app_module.runtime.hindsight = SimpleNamespace(
        list_banks=AsyncMock(
            return_value={
                "banks": [
                    {"bank_id": "alpha-only", "name": "Alpha"},
                    {"bank_id": "shared", "name": "Shared"},
                ],
                "total": 2,
                "limit": 100,
                "offset": 0,
            }
        )
    )
    app_module.runtime.policy = SimpleNamespace(
        registry=SimpleNamespace(writers={}),
        limits=SimpleNamespace(
            assert_retain_bounds=Mock(),
            assert_recall_bounds=Mock(),
        ),
        retain_bank=AsyncMock(return_value={"retained": True}),
        recall_bank=AsyncMock(return_value={"results": []}),
        deny_endpoint=AsyncMock(return_value={"error": "endpoint_not_allowed"}),
    )
    yield
    app_module.runtime.principal_resolver = None
    app_module.runtime.principal_concurrency_limiter = None
    app_module.runtime.principal_concurrency = {}


def _payload(response: object) -> object:
    return json.loads(response.body)  # type: ignore[attr-defined]


def test_scope_vocabulary_matches_specification() -> None:
    assert (
        frozenset(
            {
                "bank.list",
                "memory.recall",
                "memory.retain",
                "memory.reflect",
                "bank.config.read",
                "bank.config.write",
                "quarantine.review",
                "quarantine.decide",
                "bank.admin",
            }
        )
        == SCOPE_VOCABULARY
    )


def test_example_registry_loads_and_authenticates() -> None:
    resolver = PrincipalResolver(load_principal_registry("principal_registry.example.json"))
    result = resolver.authenticate(f"Bearer mr_writer-1_{ALPHA_SECRET}")
    assert result.status == "ok"
    session = result.session
    assert session is not None
    assert session.principal_id == "service-writer"
    assert resolver.list_banks(session) == ["project"]
    assert resolver.authorize(session, "memory.retain", "project")
    assert not resolver.authorize(session, "bank.admin", "project")
    assert resolver.authorize(session, "bank.config.read", "project")
    assert session.limits["retain"].rate_limit_max == 20


@pytest.mark.parametrize(
    "override",
    [
        {"principals": {}},
        {"principals": {"bad id": {"keys": [], "grants": []}}},
        {"principals": {"..": {"keys": [], "grants": []}}},
        {"principals": {"a": {"keys": [{"id": "k", "sha256": "z" * 64}], "grants": []}}},
        {
            "principals": {
                "a": {
                    "keys": [{"id": "k", "sha256": "A" * 64, "created_at": CREATED}],
                    "grants": [],
                }
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [{"id": "k?bad", "sha256": "a" * 64, "created_at": CREATED}],
                    "grants": [],
                }
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [{"id": "k", "sha256": "a" * 64, "created_at": "not-a-date"}],
                    "grants": [],
                }
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [{"id": "k", "sha256": "a" * 64, "created_at": "2026-09-01T00:00:00"}],
                    "grants": [],
                }
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [
                        {
                            "id": "k",
                            "sha256": "a" * 64,
                            "created_at": CREATED,
                            "expires_at": CREATED,
                        }
                    ],
                    "grants": [],
                }
            }
        },
        {
            "principals": {
                "a": {"keys": [_key("k", "a" * 64)], "grants": []},
                "b": {"keys": [_key("k", "b" * 64)], "grants": []},
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [_key("k", "a" * 64)],
                    "grants": [{"bank": "x", "scopes": ["memories:fly"]}],
                }
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [_key("k", "a" * 64)],
                    "grants": [{"bank": "x", "scopes": []}],
                }
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [_key("k", "a" * 64)],
                    "grants": [{"bank": "bad bank", "scopes": ["bank.list"]}],
                }
            }
        },
        {"principals": {"a": {"keys": [], "grants": []}}},
        {"extra": {}},
    ],
)
def test_registry_rejects_invalid_shapes(tmp_path: Path, override: dict[str, object]) -> None:
    with pytest.raises(RuntimeError):
        load_principal_registry(_write_registry(tmp_path, override))


def test_registry_rejects_unreadable_and_malformed_files(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        load_principal_registry(str(tmp_path / "missing.json"))
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    with pytest.raises(RuntimeError):
        load_principal_registry(str(path))


@pytest.mark.parametrize(
    "grants",
    [
        [
            {"bank": "shared", "scopes": ["memory.recall"]},
            {"bank": "shared", "scopes": ["memory.retain"]},
        ],
        [{"bank": "shared", "scopes": ["memory.recall", "memory.recall"]}],
    ],
)
def test_registry_rejects_duplicate_grants(tmp_path: Path, grants: list[dict[str, object]]) -> None:
    value = {"principals": {"agent": {"keys": [_key("key", ALPHA_SECRET)], "grants": grants}}}
    with pytest.raises(RuntimeError):
        load_principal_registry(_write_registry(tmp_path, value))


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer",
        "Token mr_alpha-1_" + ALPHA_SECRET,
        "Bearer alpha-1_" + ALPHA_SECRET,
        "Bearer mr_alpha-1_" + ALPHA_SECRET.upper().replace("A", "A"),
        "Bearer mr_alpha-1_" + ALPHA_SECRET[:-1],
        "Bearer mr__" + ALPHA_SECRET,
        "Bearer mr_alpha-1",
    ],
)
def test_malformed_tokens_never_authenticate(tmp_path: Path, header: str | None) -> None:
    assert _resolver(tmp_path).authenticate(header).status == "invalid-format"
    assert _resolver(tmp_path).authenticate(header).session is None


def test_authentication_rotation_lookup_and_denials(tmp_path: Path) -> None:
    resolver = _resolver(tmp_path)
    current = resolver.authenticate(_bearer("alpha-1", ALPHA_SECRET))
    rotated = resolver.authenticate(_bearer("alpha-old", OLD_ALPHA_SECRET))
    assert current.status == rotated.status == "ok"
    assert current.session is not None and rotated.session is not None
    assert current.session.principal_id == rotated.session.principal_id == "agent-alpha"
    assert {current.session.key_id, rotated.session.key_id} == {"alpha-1", "alpha-old"}
    assert resolver.authenticate(_bearer("alpha-1", "0" * 64)).status == "wrong-secret"
    assert resolver.authenticate(_bearer("unknown-key", ALPHA_SECRET)).status == "unknown-key"


def test_expired_and_revoked_keys_are_rejected_with_distinct_statuses(tmp_path: Path) -> None:
    value = _registry_value()
    alpha = value["principals"]["agent-alpha"]  # type: ignore[index]
    alpha["keys"][0]["revoked_at"] = "2026-01-15T00:00:00Z"
    alpha["keys"][1]["created_at"] = "2026-01-01T00:00:00Z"
    alpha["keys"][1]["expires_at"] = "2026-02-01T00:00:00Z"
    resolver = PrincipalResolver(load_principal_registry(_write_registry(tmp_path, value)))
    assert resolver.authenticate(_bearer("alpha-old", OLD_ALPHA_SECRET)).status == "revoked"
    assert resolver.authenticate(_bearer("alpha-1", ALPHA_SECRET)).status == "expired"
    before_expiry = datetime(2026, 1, 15, tzinfo=UTC)
    assert resolver.authenticate(_bearer("alpha-1", ALPHA_SECRET), now=before_expiry).status == "ok"


def test_unknown_key_id_still_runs_the_digest_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compared: list[bytes] = []
    real_compare = hmac.compare_digest

    def recording_compare(a: bytes, b: bytes) -> bool:
        compared.append(b)
        return real_compare(a, b)

    monkeypatch.setattr("memory_router.principals.hmac.compare_digest", recording_compare)
    resolver = _resolver(tmp_path)
    assert resolver.authenticate(_bearer("missing-key", ALPHA_SECRET)).status == "unknown-key"
    assert compared == [hashlib.sha256(b"memory-router:unknown-key").digest()]


def test_authorize_is_default_deny(tmp_path: Path) -> None:
    resolver = _resolver(tmp_path)
    result = resolver.authenticate(_bearer("reader-1", READER_SECRET))
    session = result.session
    assert session is not None
    assert resolver.authorize(session, "memory.recall", "shared")
    assert not resolver.authorize(session, "memory.retain", "shared")
    assert not resolver.authorize(session, "memory.recall", "alpha-only")
    assert resolver.list_banks(session) == []


def test_facade_scope_covers_every_route_within_vocabulary() -> None:
    mapped = {facade_scope(route) for route in FACADE_ROUTES}
    assert mapped == SCOPE_VOCABULARY - {"bank.list", "quarantine.review", "quarantine.decide"}
    by_template = {(route.method, route.template): facade_scope(route) for route in FACADE_ROUTES}
    assert by_template[("POST", "reflect")] == "memory.reflect"
    assert by_template[("POST", "memories/dry-run-extract")] == "memory.retain"
    assert by_template[("PUT", "")] == "bank.admin"
    assert by_template[("GET", "config")] == "bank.config.read"
    assert by_template[("PATCH", "config")] == "bank.config.write"
    assert by_template[("GET", "operations")] == "bank.config.read"
    assert by_template[("POST", "operations/{operation_id}/retry")] == "bank.admin"
    assert by_template[("GET", "memories/list")] == "memory.recall"
    assert by_template[("PATCH", "documents/{document_id}")] == "memory.retain"
    assert by_template[("GET", "stats")] == "bank.config.read"
    assert by_template[("POST", "consolidate")] == "bank.admin"


def test_principal_mode_rejects_legacy_token_and_anonymous_at_startup() -> None:
    base = RouterSettings(MEMORY_ROUTER_PRINCIPALS="/app/principals.json")
    assert_auth_environment(base)
    with pytest.raises(RuntimeError, match="MEMORY_ROUTER_TOKEN must be unset"):
        assert_auth_environment(
            RouterSettings(
                MEMORY_ROUTER_PRINCIPALS="/app/principals.json",
                MEMORY_ROUTER_TOKEN="legacy",  # noqa: S106 - synthetic test credential
            )
        )
    with pytest.raises(RuntimeError, match="MEMORY_ROUTER_ALLOW_ANONYMOUS must be false"):
        assert_auth_environment(
            RouterSettings(
                MEMORY_ROUTER_PRINCIPALS="/app/principals.json",
                MEMORY_ROUTER_ALLOW_ANONYMOUS=True,
            )
        )


@pytest.mark.asyncio
async def test_unauthenticated_requests_fail_closed_and_are_audited() -> None:
    response = await app_module.dispatch(
        "x", request("GET", "/v1/default/banks", headers={"authorization": _bearer("a", "0" * 64)})
    )
    assert response.status_code == 401
    app_module.runtime.auditor.persist.assert_awaited_once()
    assert app_module.runtime.auditor.log_failure.call_args.kwargs["reason"] == "unknown-key-id"


@pytest.mark.asyncio
async def test_expired_token_is_rejected_and_audited(tmp_path: Path) -> None:
    value = _registry_value()
    alpha_keys = value["principals"]["agent-alpha"]["keys"]  # type: ignore[index]
    alpha_keys[1]["created_at"] = "2026-01-01T00:00:00Z"
    alpha_keys[1]["expires_at"] = "2026-02-01T00:00:00Z"
    app_module.runtime.principal_resolver = PrincipalResolver(
        load_principal_registry(_write_registry(tmp_path, value))
    )
    response = await app_module.dispatch(
        "x",
        request(
            "GET",
            "/v1/default/banks",
            headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
        ),
    )
    assert response.status_code == 401
    assert app_module.runtime.auditor.log_failure.call_args.kwargs["reason"] == "expired-token"


@pytest.mark.asyncio
async def test_revoked_token_is_rejected_and_audited(tmp_path: Path) -> None:
    value = _registry_value()
    value["principals"]["agent-alpha"]["keys"][0]["revoked_at"] = "2026-01-15T00:00:00Z"  # type: ignore[index]
    app_module.runtime.principal_resolver = PrincipalResolver(
        load_principal_registry(_write_registry(tmp_path, value))
    )
    response = await app_module.dispatch(
        "x",
        request(
            "GET",
            "/v1/default/banks",
            headers={"authorization": _bearer("alpha-old", OLD_ALPHA_SECRET)},
        ),
    )
    assert response.status_code == 401
    assert app_module.runtime.auditor.log_failure.call_args.kwargs["reason"] == "revoked-token"


@pytest.mark.asyncio
async def test_retain_and_recall_follow_grants() -> None:
    retain = await app_module.dispatch(
        "x",
        request(
            "POST",
            "/v1/default/banks/shared/memories",
            headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
            body={"items": [{"content": "hello"}]},
        ),
    )
    assert retain.status_code == 200
    app_module.runtime.policy.retain_bank.assert_awaited_once()
    identity, bank = app_module.runtime.policy.retain_bank.await_args.args[:2]
    assert (identity, bank) == ("agent-alpha", "shared")

    recall = await app_module.dispatch(
        "x",
        request(
            "POST",
            "/v1/default/banks/shared/memories/recall",
            headers={"authorization": _bearer("reader-1", READER_SECRET)},
            body={"query": "hello"},
        ),
    )
    assert recall.status_code == 200
    app_module.runtime.policy.recall_bank.assert_awaited_once()
    identity, bank = app_module.runtime.policy.recall_bank.await_args.args[:2]
    assert (identity, bank) == ("agent-reader", "shared")


@pytest.mark.asyncio
async def test_ungranted_bank_or_scope_is_denied_before_policy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    for path, key_id, secret in [
        ("/v1/default/banks/alpha-only/memories", "alpha-1", ALPHA_SECRET),
        ("/v1/default/banks/shared/memories", "reader-1", READER_SECRET),
    ]:
        with pytest.raises(HttpError) as denial:
            await app_module.dispatch(
                "x",
                request(
                    "POST",
                    path,
                    headers={"authorization": _bearer(key_id, secret)},
                    body={"items": [{"content": "x"}]},
                ),
            )
        assert denial.value.status == 403
        assert denial.value.code == "authorization_denied"
    app_module.runtime.policy.retain_bank.assert_not_awaited()
    denials = [
        record
        for record in caplog.records
        if record.msg == "authorization_decision" and getattr(record, "decision", None) == "deny"
    ]
    assert len(denials) == 2
    assert {record.bank for record in denials} == {"alpha-only", "shared"}


@pytest.mark.asyncio
async def test_allowed_decisions_are_audited_with_spec_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    with caplog.at_level(logging.INFO):
        response = await app_module.dispatch(
            "x",
            request(
                "POST",
                "/v1/default/banks/shared/memories/recall",
                headers={"authorization": _bearer("reader-1", READER_SECRET)},
                body={"query": "hello"},
            ),
        )
    assert response.status_code == 200
    allows = [
        record
        for record in caplog.records
        if record.msg == "authorization_decision" and getattr(record, "decision", None) == "allow"
    ]
    assert allows
    record = allows[0]
    assert record.principal == "agent-reader"
    assert record.token_key_id == "reader-1"  # noqa: S105 - field name, not a secret
    assert record.bank == "shared"
    assert record.operation == "memory.recall"
    assert record.status == 200
    assert record.source == "http"
    assert isinstance(record.latency_ms, (int, float))


@pytest.mark.asyncio
async def test_bank_listing_is_filtered_and_requires_list_scope(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO):
        listed = await app_module.dispatch(
            "x",
            request(
                "GET",
                "/v1/default/banks",
                headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
            ),
        )
    assert listed.status_code == 200
    assert _payload(listed) == {
        "banks": [
            {"bank_id": "alpha-only", "name": "Alpha"},
            {"bank_id": "shared", "name": "Shared"},
        ],
        "total": 2,
        "limit": 100,
        "offset": 0,
    }
    app_module.runtime.hindsight.list_banks.assert_awaited_once_with(
        ["alpha-only", "shared"], q=None, limit=100, offset=0
    )
    listed_banks = {
        record.bank
        for record in caplog.records
        if record.msg == "authorization_decision"
        and getattr(record, "operation", None) == "bank.list"
        and getattr(record, "decision", None) == "allow"
    }
    assert listed_banks == {"alpha-only", "shared"}
    with pytest.raises(HttpError) as denial:
        await app_module.dispatch(
            "x",
            request(
                "GET",
                "/v1/default/banks",
                headers={"authorization": _bearer("reader-1", READER_SECRET)},
            ),
        )
    assert denial.value.status == 403


@pytest.mark.asyncio
async def test_claimed_agent_header_must_match_principal() -> None:
    with pytest.raises(HttpError) as mismatch:
        await app_module.dispatch(
            "x",
            request(
                "GET",
                "/v1/default/banks",
                headers={
                    "authorization": _bearer("alpha-1", ALPHA_SECRET),
                    "x-memory-router-agent": "agent-reader",
                },
            ),
        )
    assert mismatch.value.status == 403
    assert mismatch.value.code == "agent_claim_mismatch"
    assert app_module.runtime.auditor.log_failure.call_args.kwargs["reason"] == (
        "agent-claim-mismatch"
    )
    matched = await app_module.dispatch(
        "x",
        request(
            "GET",
            "/v1/default/banks",
            headers={
                "authorization": _bearer("alpha-1", ALPHA_SECRET),
                "x-memory-router-agent": "agent-alpha",
            },
        ),
    )
    assert matched.status_code == 200


@pytest.mark.asyncio
async def test_principal_rate_limit_returns_429() -> None:
    app_module.runtime.principal_limiter = SimpleNamespace(
        consume_many=AsyncMock(side_effect=HttpError(429, "rate_limited", "limited"))
    )
    with pytest.raises(HttpError) as throttled:
        await app_module.dispatch(
            "x",
            request(
                "GET",
                "/v1/default/banks",
                headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
            ),
        )
    assert throttled.value.status == 429
    assert throttled.value.code == "principal_rate_limited"


@pytest.mark.asyncio
async def test_principal_rate_storage_failure_returns_503(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_module.runtime.principal_limiter = SimpleNamespace(
        consume_many=AsyncMock(side_effect=OSError("database unavailable"))
    )

    with pytest.raises(HttpError) as unavailable:
        await app_module.dispatch(
            "x",
            request(
                "GET",
                "/v1/default/banks",
                headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
            ),
        )

    assert unavailable.value.status == 503
    assert unavailable.value.code == "principal_rate_unavailable"
    assert unavailable.value.headers == {"retry-after": "1"}
    app_module.runtime.hindsight.list_banks.assert_not_awaited()
    record = next(record for record in caplog.records if record.msg == "principal_rate_unavailable")
    assert record.operation == "consume-principal-rate"
    assert record.error_kind == "storage"
    assert record.http_status == 503
    assert record.outcome == "degraded"
    assert record.error_fingerprint
    assert not any(record.msg == "logging_contract_violation" for record in caplog.records)


@pytest.mark.asyncio
async def test_principal_concurrency_limit_returns_429(tmp_path: Path) -> None:
    value = _registry_value()
    value["principals"]["agent-alpha"]["limits"] = {  # type: ignore[index]
        "retain": {"concurrency_max": 1}
    }
    app_module.runtime.principal_resolver = PrincipalResolver(
        load_principal_registry(_write_registry(tmp_path, value))
    )
    app_module.runtime.principal_concurrency = {("agent-alpha", "retain"): 1}
    with pytest.raises(HttpError) as throttled:
        await app_module.dispatch(
            "x",
            request(
                "POST",
                "/v1/default/banks/shared/memories",
                headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
                body={"items": [{"content": "x"}]},
            ),
        )
    assert throttled.value.status == 429
    assert throttled.value.code == "principal_concurrency_limited"
    app_module.runtime.policy.retain_bank.assert_not_awaited()


@pytest.mark.asyncio
async def test_distributed_principal_concurrency_limit_returns_429() -> None:
    app_module.runtime.principal_concurrency_limiter = SimpleNamespace(
        run=AsyncMock(
            side_effect=HttpError(
                429,
                "principal_concurrency_limited",
                "too many concurrent requests for principal",
                {"retry-after": "1"},
            )
        )
    )

    with pytest.raises(HttpError) as throttled:
        await app_module.dispatch(
            "x",
            request(
                "POST",
                "/v1/default/banks/shared/memories",
                headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
                body={"items": [{"content": "x"}]},
            ),
        )

    assert throttled.value.code == "principal_concurrency_limited"
    assert throttled.value.headers == {"retry-after": "1"}
    app_module.runtime.policy.retain_bank.assert_not_awaited()


@pytest.mark.asyncio
async def test_distributed_concurrency_preserves_operation_429() -> None:
    upstream = HttpError(429, "hindsight_rate_limited", "too many recalls", {"retry-after": "9"})
    app_module.runtime.policy.recall_bank.side_effect = upstream

    async def run(_: str, __: int, operation: Callable[[], Awaitable[Any]]) -> object:
        return await operation()

    app_module.runtime.principal_concurrency_limiter = SimpleNamespace(run=run)

    with pytest.raises(HttpError) as throttled:
        await app_module.dispatch(
            "x",
            request(
                "POST",
                "/v1/default/banks/shared/memories/recall",
                headers={"authorization": _bearer("reader-1", READER_SECRET)},
                body={"query": "x"},
            ),
        )

    assert throttled.value is upstream


@pytest.mark.asyncio
async def test_distributed_concurrency_maps_lost_lease_to_503(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_module.runtime.principal_concurrency_limiter = SimpleNamespace(
        run=AsyncMock(side_effect=ConcurrencyLeaseLost("lost"))
    )

    with pytest.raises(HttpError) as unavailable:
        await app_module.dispatch(
            "x",
            request(
                "POST",
                "/v1/default/banks/shared/memories/recall",
                headers={"authorization": _bearer("reader-1", READER_SECRET)},
                body={"query": "x"},
            ),
        )

    assert unavailable.value.status == 503
    assert unavailable.value.code == "principal_concurrency_unavailable"
    assert unavailable.value.headers == {"retry-after": "1"}
    app_module.runtime.policy.recall_bank.assert_not_awaited()
    record = next(
        record for record in caplog.records if record.msg == "principal_concurrency_unavailable"
    )
    assert record.operation == "manage-concurrency-lease"
    assert record.error_kind == "storage"
    assert record.http_status == 503
    assert record.outcome == "degraded"
    assert record.error_fingerprint
    assert not any(record.msg == "logging_contract_violation" for record in caplog.records)


@pytest.mark.asyncio
async def test_distributed_principal_concurrency_wraps_operation() -> None:
    async def run(bucket: str, maximum: int, operation: Callable[[], Awaitable[Any]]) -> object:
        assert bucket == "agent-alpha:retain"
        assert maximum == 2
        return await operation()

    app_module.runtime.principal_concurrency_limiter = SimpleNamespace(run=run)

    response = await app_module.dispatch(
        "x",
        request(
            "POST",
            "/v1/default/banks/shared/memories",
            headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
            body={"items": [{"content": "x"}]},
        ),
    )

    assert response.status_code == 200
    app_module.runtime.policy.retain_bank.assert_awaited_once()


@pytest.mark.asyncio
async def test_principal_operation_limits_and_overrides(tmp_path: Path) -> None:
    value = _registry_value()
    value["defaults"] = {"limits": {"recall": {"rate_limit_max": 77}}}
    value["principals"]["agent-reader"]["limits"] = {  # type: ignore[index]
        "recall": {"rate_limit_max": 3, "rate_limit_window_ms": 2_000}
    }
    app_module.runtime.principal_resolver = PrincipalResolver(
        load_principal_registry(_write_registry(tmp_path, value))
    )
    response = await app_module.dispatch(
        "x",
        request(
            "POST",
            "/v1/default/banks/shared/memories/recall",
            headers={"authorization": _bearer("reader-1", READER_SECRET)},
            body={"query": "hello"},
        ),
    )
    assert response.status_code == 200
    app_module.runtime.principal_limiter.consume_many.assert_awaited_once_with(
        [("principal:agent-reader:recall", 3, 2_000)]
    )


@pytest.mark.asyncio
async def test_principal_body_limit_is_enforced_before_policy(tmp_path: Path) -> None:
    value = _registry_value()
    value["principals"]["agent-alpha"]["limits"] = {  # type: ignore[index]
        "retain": {"max_body_bytes": 8}
    }
    app_module.runtime.principal_resolver = PrincipalResolver(
        load_principal_registry(_write_registry(tmp_path, value))
    )
    with pytest.raises(HttpError) as too_large:
        await app_module.dispatch(
            "x",
            request(
                "POST",
                "/v1/default/banks/shared/memories",
                headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
                body={"items": [{"content": "large"}]},
            ),
        )
    assert too_large.value.status == 413
    app_module.runtime.policy.retain_bank.assert_not_awaited()


@pytest.mark.asyncio
async def test_facade_routes_enforce_scope_and_forward_target_bank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forward = AsyncMock(return_value={"config": {}})
    facade = SimpleNamespace(forward=forward)
    monkeypatch.setattr(app_module, "OpenClawFacade", Mock(return_value=facade))

    allowed = await app_module.dispatch(
        "x",
        request(
            "GET",
            "/v1/default/banks/shared/mental-models",
            headers={"authorization": _bearer("reader-1", READER_SECRET)},
        ),
    )
    assert allowed.status_code == 200
    forward.assert_awaited_once()
    assert forward.await_args.kwargs["writer_id"] == "agent-reader"
    assert forward.await_args.kwargs["bank_override"] == "shared"

    with pytest.raises(HttpError) as denial:
        await app_module.dispatch(
            "x",
            request(
                "GET",
                "/v1/default/banks/shared/config",
                headers={"authorization": _bearer("reader-1", READER_SECRET)},
            ),
        )
    assert denial.value.status == 403
    assert forward.await_count == 1


@pytest.mark.asyncio
async def test_facade_write_scope_is_enforced() -> None:
    with pytest.raises(HttpError) as denial:
        await app_module.dispatch(
            "x",
            request(
                "PATCH",
                "/v1/default/banks/shared/config",
                headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
                body={"retain_mission": "x"},
            ),
        )
    assert denial.value.status == 403
    assert denial.value.code == "authorization_denied"


@pytest.mark.asyncio
async def test_unmatched_paths_keep_policy_denial_with_principal_identity() -> None:
    response = await app_module.dispatch(
        "x",
        request(
            "GET",
            "/v1/default/banks/shared/export",
            headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
        ),
    )
    assert response.status_code == 404
    app_module.runtime.policy.deny_endpoint.assert_awaited_once()
    assert app_module.runtime.policy.deny_endpoint.await_args.kwargs["writer_id"] == "agent-alpha"


@pytest.mark.asyncio
async def test_policy_bank_paths_use_principal_identity() -> None:
    from memory_router.policy import RouterPolicy

    policy = RouterPolicy(
        SimpleNamespace(writers={}),
        SimpleNamespace(
            retain=AsyncMock(return_value={"success": True}),
            recall=AsyncMock(return_value={"results": []}),
        ),
        SimpleNamespace(consume_retain=AsyncMock(), consume_recall=AsyncMock()),
        SimpleNamespace(put=AsyncMock(return_value={"quarantine_id": "q1"})),
        SimpleNamespace(),
    )
    retained = await policy.retain_bank("agent-alpha", "shared", {"items": [{"content": "note"}]})
    assert retained == {"success": True}
    bank, body = policy.hindsight.retain.await_args.args
    assert bank == "shared"
    assert body["items"][0]["metadata"]["router_writer_id"] == "agent-alpha"
    assert body["items"][0]["metadata"]["router_target_bank"] == "shared"
    assert await policy.recall_bank("agent-alpha", "shared", {"query": "note"}) == {"results": []}
    policy.hindsight.recall.assert_awaited_once()


def test_audit_fields_are_sanitized_and_never_carry_secrets() -> None:
    fields = sanitize_fields(
        {
            "principal": "agent-alpha",
            "token_key_id": "reader-1",
            "bank": "shared",
            "scope": "memory.recall",
            "decision": "allow",
            "status": 200,
            "latency_ms": 0.25,
            "source": "http",
            "partial": False,
            "event": "authorization_decision",
        }
    )
    assert fields["principal"] == "agent-alpha"
    assert fields["token_key_id"] == "reader-1"  # noqa: S105 - field name, not a secret
    assert fields["bank"] == "shared"
    assert fields["scope"] == "memory.recall"
    assert fields["decision"] == "allow"
    assert fields["status"] == 200
    assert fields["latency_ms"] == 0.25
    assert fields["source"] == "http"
    assert fields["partial"] is False
    dropped = sanitize_fields(
        {
            "principal": "bad principal",
            "token_key_id": "not a key",
            "bank": "bad bank",
            "scope": "memories:fly",
            "decision": "maybe",
            "partial": "yes",
        }
    )
    assert "scope" not in dropped and "decision" not in dropped and "partial" not in dropped
    assert dropped["principal"].startswith("principal:")
    assert dropped["bank"].startswith("bank:")
    assert dropped["token_key_id"].startswith("token_key_id:")
    assert ALPHA_SECRET not in json.dumps(fields)
