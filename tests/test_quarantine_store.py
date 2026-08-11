from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.errors import HttpError
from memory_router.quarantine_store import (
    QuarantineLimits,
    QuarantineStore,
    _effective_writer_limit,
)
from memory_router.rate_limit import PostgresRateLimiter


def public_key() -> str:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


class Session:
    def __init__(self) -> None:
        self.count_calls: list[object] = []
        self.distinct_calls: list[object] = []
        self.error: HttpError | None = None

    async def consume_many(self, buckets: object) -> None:
        self.count_calls.append(buckets)
        if self.error:
            raise self.error

    async def consume_many_distinct(self, buckets: object, identities: object) -> None:
        self.distinct_calls.append((buckets, identities))
        if self.error:
            raise self.error


class Limiter:
    def __init__(self) -> None:
        self.session = Session()

    async def consume_many(self, buckets: object) -> None:
        await self.session.consume_many(buckets)

    async def consume_many_distinct(self, buckets: object, identities: object) -> None:
        await self.session.consume_many_distinct(buckets, identities)

    async def with_identity_lock(self, identity: str, operation: object) -> object:
        return await operation(self.session)  # type: ignore[operator]


class FakePostgresTx:
    dialect = "postgres"

    def __init__(self, state: dict[str, object]) -> None:
        self.state = state

    async def execute(self, sql: str, params: object = None) -> None:
        values = tuple(params or ())  # type: ignore[arg-type]
        if "INSERT INTO quarantine_rate_limit_state" in sql:
            self.state["max_window"] = max(int(self.state["max_window"]), int(values[0]))
        elif "INSERT INTO quarantine_rate_limit_events" in sql:
            events = self.state["events"]
            assert isinstance(events, list)
            events.append((str(values[0]), int(values[1])))
        elif "DELETE FROM quarantine_rate_limit_events WHERE bucket" in sql:
            events = self.state["events"]
            assert isinstance(events, list)
            bucket, cutoff = str(values[0]), int(values[1])
            self.state["events"] = [
                event for event in events if event[0] != bucket or event[1] > cutoff
            ]

    async def fetchone(self, sql: str, params: object = None) -> dict[str, int] | None:
        values = tuple(params or ())  # type: ignore[arg-type]
        if "clock_timestamp" in sql:
            return {"now_ms": 100_000}
        if "SELECT max_window_ms" in sql:
            return {"max_window_ms": int(self.state["max_window"])}
        if "COUNT(*)" in sql and "quarantine_rate_limit_events" in sql:
            events = self.state["events"]
            assert isinstance(events, list)
            bucket = str(values[0])
            return {"count": sum(1 for event in events if event[0] == bucket)}
        return None


class FakePostgresDatabase:
    def __init__(self) -> None:
        self.state: dict[str, object] = {"events": [], "max_window": 0}

    @asynccontextmanager
    async def transaction(self):  # type: ignore[no-untyped-def]
        working = {
            "events": list(self.state["events"]),  # type: ignore[arg-type]
            "max_window": self.state["max_window"],
        }
        try:
            yield FakePostgresTx(working)
        except Exception:
            raise
        else:
            self.state = working


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


def store_fixture(
    limits: QuarantineLimits | None = None,
) -> tuple[QuarantineStore, SimpleNamespace, Limiter]:
    repository = SimpleNamespace(
        get=AsyncMock(return_value=None),
        find_memory_state=AsyncMock(return_value=None),
        store=AsyncMock(),
    )
    limiter = Limiter()
    return (
        QuarantineStore(public_key(), repository, limits or QuarantineLimits(), limiter),
        repository,
        limiter,
    )


def test_effective_writer_limit() -> None:
    assert _effective_writer_limit(QuarantineLimits(max_pending_items_per_writer=0)) == 0
    assert _effective_writer_limit(QuarantineLimits(max_pending_items=1)) == 0
    assert (
        _effective_writer_limit(
            QuarantineLimits(
                max_pending_items=10,
                max_pending_items_per_writer=5,
                max_encrypted_bytes=100,
                max_item_bytes=20,
            )
        )
        == 4
    )


def test_resolve_id_modes_and_ttl() -> None:
    store, _, _ = store_fixture(QuarantineLimits(item_ttl_days=1))
    security = store._resolve_id(base_input("security_event", dedupeKey="k"))
    request = store._resolve_id(base_input("recall_request", dedupeKey="k"))
    memory = store._resolve_id(base_input("recalled_memory", sourceBank="main", sourceMemoryId="m"))
    random_id = store._resolve_id(base_input("retain_request"))
    assert (
        security.startswith("q_security")
        and request.startswith("q_request")
        and memory.startswith("q_memory")
        and random_id.startswith("q_20260808")
    )
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
    store, _, _ = store_fixture(QuarantineLimits(max_item_bytes=1))
    with pytest.raises(HttpError) as too_large:
        await store.put(base_input())
    assert too_large.value.code == "quarantine_item_too_large"

    store, repository, _ = store_fixture()
    repository.get.return_value = {"status": "reviewed_allowed"}
    with pytest.raises(HttpError) as reviewed:
        await store.put(base_input(dedupeKey="d"))
    assert reviewed.value.code == "quarantine_request_in_review"


@pytest.mark.asyncio
async def test_oversize_is_rejected_before_encrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    store, repository, limiter = store_fixture(QuarantineLimits(max_item_bytes=1))
    encrypt = MagicMock()
    monkeypatch.setattr(store, "_encrypt", encrypt)
    with pytest.raises(HttpError) as too_large:
        await store.put(base_input())
    assert too_large.value.code == "quarantine_item_too_large"
    encrypt.assert_not_called()
    repository.store.assert_not_awaited()
    assert not limiter.session.count_calls
    assert not limiter.session.distinct_calls


@pytest.mark.asyncio
async def test_review_in_progress_is_rejected_before_encrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, repository, _ = store_fixture()
    repository.get.return_value = {"status": "review_in_progress"}
    encrypt = MagicMock()
    monkeypatch.setattr(store, "_encrypt", encrypt)
    with pytest.raises(HttpError) as review:
        await store.put(base_input())
    assert review.value.code == "quarantine_item_in_review"
    encrypt.assert_not_called()


@pytest.mark.asyncio
async def test_known_identity_variants() -> None:
    store, repository, _ = store_fixture()
    assert await store._known_identity(base_input("security_event", dedupeKey="x"), True)
    repository.find_memory_state.return_value = {"status": "pending"}
    assert await store._known_identity(
        base_input("recalled_memory", sourceBank="main", sourceMemoryId="m"), False
    )
    assert not await store._known_identity(base_input("retain_request"), False)


@pytest.mark.asyncio
async def test_charge_known_disabled_auth_and_family() -> None:
    store, _, limiter = store_fixture()
    session = limiter.session
    await store._charge(base_input(), True, session)
    assert "requarantine" in str(session.count_calls[-1])
    await store._charge(base_input(reason="auth_failed"), True, session)
    assert "auth-audit" in str(session.count_calls[-1])

    disabled, _, limiter2 = store_fixture(QuarantineLimits(rate_limit_max=0))
    await disabled._charge(base_input(), False, limiter2.session)
    assert not limiter2.session.distinct_calls

    await store._charge(base_input(reason="auth_failed"), False, session)
    assert "auth-audit" in str(session.count_calls[-1])
    await store._charge(base_input(dedupeKey="x"), False, session)
    buckets, identities = session.distinct_calls[-1]
    assert "writer:main" in str(buckets) and identities


@pytest.mark.asyncio
async def test_rate_limit_failure_happens_before_encryption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, repository, limiter = store_fixture()
    limiter.session.error = HttpError(429, "quarantine_rate_limited", "too many quarantine writes")
    encrypt = MagicMock()
    monkeypatch.setattr(store, "_encrypt", encrypt)
    with pytest.raises(HttpError) as limited:
        await store.put(base_input(dedupeKey="d"))
    assert limited.value.code == "quarantine_rate_limited"
    encrypt.assert_not_called()
    repository.store.assert_not_awaited()


@pytest.mark.asyncio
async def test_oversize_preflight_preserves_rate_budget_for_bounded_placeholder() -> None:
    database = FakePostgresDatabase()
    limiter = PostgresRateLimiter(database)
    repository = SimpleNamespace(
        get=AsyncMock(return_value=None),
        find_memory_state=AsyncMock(return_value=None),
        store=AsyncMock(),
    )
    store = QuarantineStore(
        public_key(),
        repository,
        QuarantineLimits(
            max_item_bytes=2_048,
            rate_limit_max=1,
            rate_limit_global_max=1,
            distinct_family_limit_max=0,
        ),
        limiter,
    )
    oversized = base_input(
        "recall_request",
        dedupeKey="oversized",
        payload={"query": "system prompt", "padding": "x" * 4_096},
    )

    with pytest.raises(HttpError) as too_large:
        await store.put(oversized)
    assert too_large.value.code == "quarantine_item_too_large"
    assert database.state["events"] == []

    placeholder = base_input(
        "security_event",
        reason="suspicious_query",
        dedupeKey="bounded-placeholder",
        payload={
            "action": "recall_request_too_large",
            "writer_id": "main",
            "content_sha256": "a" * 64,
            "findings": [{"matched": "system prompt", "reason": "prompt_injection"}],
        },
    )
    result = await store.put(placeholder)

    assert result["quarantine_id"].startswith("q_security")
    assert len(database.state["events"]) == 2  # type: ignore[arg-type]
    repository.store.assert_awaited_once()


@pytest.mark.asyncio
async def test_postgres_rate_charge_survives_failed_quarantine_write() -> None:
    database = FakePostgresDatabase()
    limiter = PostgresRateLimiter(database)
    repository = SimpleNamespace(
        get=AsyncMock(return_value=None),
        find_memory_state=AsyncMock(return_value=None),
        store=AsyncMock(
            side_effect=HttpError(507, "quarantine_capacity_exceeded", "quarantine is full")
        ),
    )
    store = QuarantineStore(
        public_key(),
        repository,
        QuarantineLimits(
            rate_limit_max=1,
            rate_limit_global_max=1,
            distinct_family_limit_max=0,
        ),
        limiter,
    )

    with pytest.raises(HttpError) as full:
        await store.put(base_input())
    assert full.value.status == 507
    assert len(database.state["events"]) == 2  # type: ignore[arg-type]

    with pytest.raises(HttpError) as limited:
        await store.put(base_input())
    assert limited.value.code == "quarantine_rate_limited"
    assert repository.store.await_count == 1
