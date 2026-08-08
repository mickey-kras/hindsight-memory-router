from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.errors import HttpError
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore, _effective_writer_limit


def public_key() -> str:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


class Session:
    def __init__(self) -> None:
        self.count_calls: list[object] = []
        self.distinct_calls: list[object] = []
    async def consume_many(self, buckets: object) -> None: self.count_calls.append(buckets)
    async def consume_many_distinct(self, buckets: object, identities: object) -> None: self.distinct_calls.append((buckets, identities))


class Limiter:
    def __init__(self) -> None:
        self.session = Session()
    async def with_identity_lock(self, identity: str, operation: object) -> object:
        return await operation(self.session)  # type: ignore[operator]


def base_input(kind: str = "retain_request", **extra: object) -> dict[str, object]:
    value: dict[str, object] = {
        "timestamp": "2026-08-08T00:00:00.000Z",
        "kind": kind,
        "reason": "suspicious_content",
        "writerId": "main",
        "source": "http",
        "payload": {"items": [{"content": "x"}]},
    }
    value.update(extra)
    return value


def store_fixture(limits: QuarantineLimits | None = None) -> tuple[QuarantineStore, SimpleNamespace, Limiter]:
    repository = SimpleNamespace(
        get=AsyncMock(return_value=None),
        find_memory_state=AsyncMock(return_value=None),
        stats=AsyncMock(return_value={"pending_items": 0, "postponed_items": 0, "encrypted_bytes": 0}),
        store=AsyncMock(),
    )
    limiter = Limiter()
    return QuarantineStore(public_key(), repository, limits or QuarantineLimits(), limiter), repository, limiter


def test_effective_writer_limit() -> None:
    assert _effective_writer_limit(QuarantineLimits(max_pending_items_per_writer=0)) == 0
    assert _effective_writer_limit(QuarantineLimits(max_pending_items=1)) == 0
    assert _effective_writer_limit(QuarantineLimits(max_pending_items=10, max_pending_items_per_writer=5, max_encrypted_bytes=100, max_item_bytes=20)) == 4


def test_resolve_id_modes_and_ttl() -> None:
    store, _, _ = store_fixture(QuarantineLimits(item_ttl_days=1))
    security = store._resolve_id(base_input("security_event", dedupeKey="k"))
    request = store._resolve_id(base_input("recall_request", dedupeKey="k"))
    memory = store._resolve_id(base_input("recalled_memory", sourceBank="main", sourceMemoryId="m"))
    random_id = store._resolve_id(base_input("retain_request"))
    assert security.startswith("q_security") and request.startswith("q_request") and memory.startswith("q_memory") and random_id.startswith("q_20260808")
    encrypted = {"sha256": "x"}
    built = store._build_item(base_input(), "q", encrypted)
    assert built["expires_at"] == "2026-08-09T00:00:00.000Z"
    with pytest.raises(HttpError, match="ISO timestamp"):
        store._build_item(base_input(timestamp="bad"), "q", encrypted)


@pytest.mark.asyncio
async def test_put_new_request_charges_and_stores() -> None:
    store, repository, limiter = store_fixture()
    result = await store.put(base_input(dedupeKey="d"))
    assert result["quarantine_id"].startswith("q_request")
    repository.store.assert_awaited_once()
    assert repository.store.await_args.kwargs["mode"] == "request"
    assert limiter.session.distinct_calls


@pytest.mark.asyncio
async def test_put_memory_and_security_event_modes() -> None:
    store, repository, _ = store_fixture()
    await store.put(base_input("recalled_memory", sourceBank="main", sourceMemoryId="m"))
    assert repository.store.await_args.kwargs["mode"] == "memory"
    await store.put(base_input("security_event", reason="auth_failed", dedupeKey="auth"))
    assert repository.store.await_args.kwargs["mode"] == "id"
    capacity = repository.store.await_args.args[1]
    assert capacity.max_pending_items_per_writer == 0


@pytest.mark.asyncio
async def test_put_rejects_oversize_and_reviewed_duplicate() -> None:
    store, repository, _ = store_fixture(QuarantineLimits(max_item_bytes=1))
    with pytest.raises(HttpError) as too_large:
        await store.put(base_input())
    assert too_large.value.code == "quarantine_item_too_large"

    store, repository, _ = store_fixture()
    repository.get.return_value = {"status": "reviewed_allowed"}
    with pytest.raises(HttpError) as reviewed:
        await store.put(base_input(dedupeKey="d"))
    assert reviewed.value.code == "quarantine_request_in_review"


@pytest.mark.asyncio
async def test_known_identity_variants() -> None:
    store, repository, _ = store_fixture()
    assert await store._known_identity(base_input("security_event", dedupeKey="x"), True)
    repository.find_memory_state.return_value = {"status": "pending"}
    assert await store._known_identity(base_input("recalled_memory", sourceBank="main", sourceMemoryId="m"), False)
    assert not await store._known_identity(base_input("retain_request"), False)


@pytest.mark.asyncio
async def test_charge_known_capacity_disabled_auth_and_family() -> None:
    store, repository, limiter = store_fixture()
    session = limiter.session
    await store._charge(base_input(), True, session)
    assert "requarantine" in str(session.count_calls[-1])
    await store._charge(base_input(reason="auth_failed"), True, session)
    assert "auth-audit" in str(session.count_calls[-1])

    disabled, _, limiter2 = store_fixture(QuarantineLimits(rate_limit_max=0))
    await disabled._charge(base_input(), False, limiter2.session)
    assert not limiter2.session.distinct_calls

    repository.stats.return_value = {"pending_items": 1000, "postponed_items": 0, "encrypted_bytes": 0}
    await store._charge(base_input(), False, session)
    calls_before = len(session.distinct_calls)
    assert calls_before == 0

    repository.stats.return_value = {"pending_items": 0, "postponed_items": 0, "encrypted_bytes": 0}
    await store._charge(base_input(reason="auth_failed"), False, session)
    assert "auth-audit" in str(session.count_calls[-1])
    await store._charge(base_input(dedupeKey="x"), False, session)
    buckets, identities = session.distinct_calls[-1]
    assert "writer:main" in str(buckets) and identities


@pytest.mark.asyncio
async def test_capacity_exhausted_by_bytes_or_counts() -> None:
    store, repository, _ = store_fixture(QuarantineLimits(max_pending_items=2, max_encrypted_bytes=10))
    repository.stats.return_value = {"pending_items": 1, "postponed_items": 1, "encrypted_bytes": 0}
    assert await store._capacity_exhausted("now")
    repository.stats.return_value = {"pending_items": 0, "postponed_items": 0, "encrypted_bytes": 10}
    assert await store._capacity_exhausted("now")
    repository.stats.return_value = {"pending_items": 0, "postponed_items": 0, "encrypted_bytes": 9}
    assert not await store._capacity_exhausted("now")
