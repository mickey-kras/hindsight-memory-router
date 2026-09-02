from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
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
from tests.request_helpers import request

ALPHA_SECRET = "a" * 64
READER_SECRET = "b" * 64
OLD_ALPHA_SECRET = "c" * 64


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _registry_value() -> dict[str, object]:
    return {
        "principals": {
            "agent-alpha": {
                "keys": [
                    {"id": "alpha-old", "sha256": _digest(OLD_ALPHA_SECRET)},
                    {"id": "alpha-1", "sha256": _digest(ALPHA_SECRET)},
                ],
                "grants": [
                    {
                        "bank": "shared",
                        "scopes": ["banks:list", "memories:retain", "memories:recall"],
                    },
                    {"bank": "alpha-only", "scopes": ["banks:list"]},
                ],
            },
            "agent-reader": {
                "keys": [{"id": "reader-1", "sha256": _digest(READER_SECRET)}],
                "grants": [{"bank": "shared", "scopes": ["memories:recall", "memories:read"]}],
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


def _payload(response: object) -> object:
    return json.loads(response.body)  # type: ignore[attr-defined]


def test_example_registry_loads_and_authenticates() -> None:
    resolver = PrincipalResolver(load_principal_registry("principal_registry.example.json"))
    session = resolver.authenticate(
        "Bearer mr_main-2026-09_9a4f2c71e83b4d05a6c98f12b3e47d05c1a8f3e69b204d7a91c5e8f0a3b6d924"
    )
    assert session is not None
    assert session.principal_id == "main"
    assert resolver.list_banks(session) == ["creative", "dev", "main"]
    assert resolver.authorize(session, "memories:retain", "main")
    assert not resolver.authorize(session, "memories:retain", "dev")
    assert not resolver.authorize(session, "banks:manage", "main")


@pytest.mark.parametrize(
    "override",
    [
        {"principals": {}},
        {"principals": {"bad id": {"keys": [], "grants": []}}},
        {"principals": {"..": {"keys": [], "grants": []}}},
        {"principals": {"a": {"keys": [{"id": "k", "sha256": "z" * 64}], "grants": []}}},
        {"principals": {"a": {"keys": [{"id": "k", "sha256": "A" * 64}], "grants": []}}},
        {"principals": {"a": {"keys": [{"id": "k?bad", "sha256": "a" * 64}], "grants": []}}},
        {
            "principals": {
                "a": {"keys": [{"id": "k", "sha256": "a" * 64}], "grants": []},
                "b": {"keys": [{"id": "k", "sha256": "b" * 64}], "grants": []},
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [{"id": "k", "sha256": "a" * 64}],
                    "grants": [{"bank": "x", "scopes": ["memories:fly"]}],
                }
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [{"id": "k", "sha256": "a" * 64}],
                    "grants": [{"bank": "x", "scopes": []}],
                }
            }
        },
        {
            "principals": {
                "a": {
                    "keys": [{"id": "k", "sha256": "a" * 64}],
                    "grants": [{"bank": "bad bank", "scopes": ["banks:list"]}],
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
    assert _resolver(tmp_path).authenticate(header) is None


def test_authentication_rotation_lookup_and_denials(tmp_path: Path) -> None:
    resolver = _resolver(tmp_path)
    current = resolver.authenticate(_bearer("alpha-1", ALPHA_SECRET))
    rotated = resolver.authenticate(_bearer("alpha-old", OLD_ALPHA_SECRET))
    assert current is not None and rotated is not None
    assert current.principal_id == rotated.principal_id == "agent-alpha"
    assert {current.key_id, rotated.key_id} == {"alpha-1", "alpha-old"}
    assert resolver.authenticate(_bearer("alpha-1", "0" * 64)) is None
    assert resolver.authenticate(_bearer("unknown-key", ALPHA_SECRET)) is None


def test_authorize_is_default_deny(tmp_path: Path) -> None:
    resolver = _resolver(tmp_path)
    session = resolver.authenticate(_bearer("reader-1", READER_SECRET))
    assert session is not None
    assert resolver.authorize(session, "memories:recall", "shared")
    assert not resolver.authorize(session, "memories:retain", "shared")
    assert not resolver.authorize(session, "memories:recall", "alpha-only")
    assert resolver.list_banks(session) == []


def test_facade_scope_covers_every_route_within_vocabulary() -> None:
    mapped = {facade_scope(route) for route in FACADE_ROUTES}
    assert mapped == SCOPE_VOCABULARY - {"banks:list", "memories:recall"}
    by_template = {(route.method, route.template): facade_scope(route) for route in FACADE_ROUTES}
    assert by_template[("POST", "reflect")] == "reflect:run"
    assert by_template[("POST", "memories/dry-run-extract")] == "memories:retain"
    assert by_template[("PUT", "")] == "banks:manage"
    assert by_template[("GET", "config")] == "banks:read"
    assert by_template[("PATCH", "config")] == "banks:manage"
    assert by_template[("GET", "operations")] == "banks:read"
    assert by_template[("POST", "operations/{operation_id}/retry")] == "operations:manage"
    assert by_template[("GET", "memories/list")] == "memories:read"
    assert by_template[("PATCH", "documents/{document_id}")] == "memories:write"


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
    denials = [record for record in caplog.records if "authorization_denied" in str(record.msg)]
    assert denials


@pytest.mark.asyncio
async def test_bank_listing_is_filtered_and_requires_list_scope() -> None:
    listed = await app_module.dispatch(
        "x",
        request(
            "GET", "/v1/default/banks", headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)}
        ),
    )
    assert listed.status_code == 200
    assert _payload(listed) == {"banks": ["alpha-only", "shared"]}
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
                "/v1/default/banks/shared/documents/doc-1",
                headers={"authorization": _bearer("alpha-1", ALPHA_SECRET)},
                body={"name": "x"},
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
            "key_id": "alpha-1",
            "scope": "memories:recall",
            "reason": "scope-not-granted",
            "event": "authorization_denied",
        }
    )
    assert fields["principal"] == "agent-alpha"
    assert fields["key_id"] == "alpha-1"
    assert fields["scope"] == "memories:recall"
    dropped = sanitize_fields(
        {
            "principal": "bad principal",
            "key_id": "not a key",
            "scope": "memories:fly",
        }
    )
    assert "key_id" not in dropped and "scope" not in dropped
    assert dropped["principal"].startswith("principal:")
    assert ALPHA_SECRET not in json.dumps(fields)
