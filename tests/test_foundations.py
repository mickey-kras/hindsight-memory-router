from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from memory_router import auth, config, dedupe, validation
from memory_router.errors import HttpError
from memory_router.limits import HindsightLimitConfig, HindsightLimits
from memory_router.rate_limit import InMemoryRateLimiter, PostgresRateLimiter, _PostgresSession


def test_auth_helpers_and_scopes() -> None:
    assert auth.bearer_matches("Bearer secret", "secret")
    assert not auth.bearer_matches(None, "secret")
    assert not auth.bearer_matches("Bearer nope", "secret")
    assert auth.router_authorized(None, None, True)
    assert not auth.router_authorized(None, None, False)
    tokens = {"legacy": "legacy", "read": "read", "review": "review", "cleanup": "clean"}
    assert auth.admin_authorized("Bearer legacy", "read", tokens)
    assert auth.admin_authorized("Bearer review", "read", tokens)
    assert auth.admin_authorized("Bearer review", "review", tokens)
    assert auth.admin_authorized("Bearer clean", "cleanup", tokens)
    assert not auth.admin_authorized("Bearer read", "review", tokens)
    assert not auth.admin_authorized("Bearer x", "unknown", tokens)


@pytest.mark.asyncio
async def test_auth_failure_auditor_records_and_survives_store_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = SimpleNamespace(put=AsyncMock())
    auditor = auth.AuthFailureAuditor(store)
    auditor.log_failure()
    await auditor.persist("router")
    auditor.log_failure()
    await auditor.persist("router")
    assert store.put.await_count == 2
    assert caplog.text.count("authentication_failed") == 1

    caplog.clear()
    store.put.side_effect = RuntimeError("down")
    await auditor.persist("admin")
    await auditor.persist("admin")
    assert caplog.text.count("authentication_audit_failed") == 1


def test_environment_parsers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INT", raising=False)
    assert config.integer_env("INT", 7, minimum=1) == 7
    monkeypatch.setenv("INT", "9")
    assert config.integer_env("INT", 7, minimum=1) == 9
    monkeypatch.setenv("INT", "bad")
    with pytest.raises(RuntimeError, match="must be an integer"):
        config.integer_env("INT", 7)
    monkeypatch.setenv("INT", "0")
    with pytest.raises(RuntimeError, match="must be >= 1"):
        config.integer_env("INT", 7, minimum=1)

    monkeypatch.delenv("BOOL", raising=False)
    assert config.boolean_env("BOOL", True)
    for raw, expected in (("true", True), ("false", False)):
        monkeypatch.setenv("BOOL", raw)
        assert config.boolean_env("BOOL") is expected
    monkeypatch.setenv("BOOL", "1")
    with pytest.raises(RuntimeError, match="true or false"):
        config.boolean_env("BOOL")


def test_registry_loading_and_validation(tmp_path: Path) -> None:
    default = config.load_registry()
    assert set(default.writers) == {"main"}
    default.writers["main"].role = "changed"
    assert config.load_registry().writers["main"].role == "default"

    valid = tmp_path / "registry.json"
    valid.write_text(
        json.dumps(
            {
                "writers": {
                    "dev": {
                        "role": "dev",
                        "source": "application",
                        "write_bank": "dev",
                        "read_banks": ["dev"],
                    }
                },
                "defaults": {
                    "unknown_writer_action": "review_queue",
                    "suspicious_content_action": "review_queue",
                },
            }
        )
    )
    assert "dev" in config.load_registry(str(valid)).writers

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}")
    with pytest.raises(RuntimeError, match="invalid writer registry"):
        config.load_registry(str(invalid))

    blank = tmp_path / "blank.json"
    blank.write_text(
        json.dumps(
            {
                "writers": {
                    " ": {"role": "x", "source": "x", "write_bank": "main", "read_banks": ["main"]}
                },
                "defaults": {
                    "unknown_writer_action": "review_queue",
                    "suspicious_content_action": "review_queue",
                },
            }
        )
    )
    with pytest.raises(RuntimeError, match="writer id cannot be empty"):
        config.load_registry(str(blank))

    cross = tmp_path / "cross.json"
    cross.write_text(
        json.dumps(
            {
                "writers": {
                    "main": {
                        "role": "x",
                        "source": "x",
                        "write_bank": "main",
                        "read_banks": ["main", "research"],
                    }
                },
                "defaults": {
                    "unknown_writer_action": "review_queue",
                    "suspicious_content_action": "review_queue",
                },
            }
        )
    )
    custom = config.load_registry(str(cross))
    assert custom.writers["main"].read_banks == ["main", "research"]


def test_environment_assertions(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for name in list(config.os.environ):
        if name.startswith("QUARANTINE_PRIVATE_KEY") or name.startswith("MEMORY_ROUTER_"):
            monkeypatch.delenv(name, raising=False)
    config.assert_no_private_key_environment()
    monkeypatch.setenv("QUARANTINE_PRIVATE_KEY", "nope")
    with pytest.raises(RuntimeError, match="must not be available"):
        config.assert_no_private_key_environment()
    monkeypatch.delenv("QUARANTINE_PRIVATE_KEY")

    config.assert_auth_environment()
    assert {
        record.reason  # type: ignore[attr-defined]
        for record in caplog.records
        if record.msg == "configuration_warning"
    } == {
        "router-token-missing",
        "admin-read-token-missing",
        "admin-review-token-missing",
        "admin-cleanup-token-missing",
    }
    caplog.clear()
    monkeypatch.setenv("MEMORY_ROUTER_ALLOW_ANONYMOUS", "true")
    monkeypatch.setenv("MEMORY_ROUTER_ADMIN_TOKEN", "legacy")
    config.assert_auth_environment()
    assert {
        record.reason  # type: ignore[attr-defined]
        for record in caplog.records
        if record.msg == "configuration_warning"
    } == {"anonymous-mode", "legacy-admin-token"}


def test_deployment_mode_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEMORY_ROUTER_DEPLOYMENT_MODE", "bad")
    with pytest.raises(RuntimeError, match="single or cluster"):
        config.assert_deployment_mode("sqlite:///x")
    monkeypatch.setenv("MEMORY_ROUTER_DEPLOYMENT_MODE", "cluster")
    monkeypatch.setenv("MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT", "false")
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        config.assert_deployment_mode("sqlite:///x")
    with pytest.raises(RuntimeError, match="EXTERNAL_ADMIN"):
        config.assert_deployment_mode("postgresql://db")
    monkeypatch.setenv("MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT", "true")
    config.assert_deployment_mode("postgresql://db")
    monkeypatch.setenv("MEMORY_ROUTER_DEPLOYMENT_MODE", "single")
    config.assert_deployment_mode("sqlite:///x")


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, "retain body must be an object"),
        ({"items": []}, "requires at least one"),
        ({"items": [1]}, "memory item 0 must be an object"),
        ({"items": [{"content": ""}]}, "content must be a non-empty string"),
        ({"items": [{"content": "x", "context": 1}]}, "context must be a string or null"),
        ({"items": [{"content": "x", "document_id": 1}]}, "document_id must be a string or null"),
        ({"items": [{"content": "x", "timestamp": 1}]}, "timestamp must be a string or null"),
        ({"items": [{"content": "x", "tags": [1]}]}, "tags must contain strings"),
        (
            {"items": [{"content": "x", "metadata": {"a": 1}}]},
            "metadata must map strings to strings",
        ),
        (
            {"items": [{"content": "x", "update_mode": "bad"}]},
            "update_mode must be replace or append",
        ),
        ({"items": [{"content": "x"}], "async": "x"}, "async must be a boolean"),
        ({"items": [{"content": "x"}], "document_tags": [1]}, "document_tags must contain strings"),
    ],
)
def test_retain_validation_errors(value: object, message: str) -> None:
    with pytest.raises(HttpError, match=message):
        validation.parse_retain_body(value)


def test_retain_validation_success_and_passthrough() -> None:
    parsed = validation.parse_retain_body(
        {"items": [{"content": "x", "extra": 1}], "async": True, "extra": "ok"}
    )
    assert parsed["async"] is True and parsed["items"][0]["extra"] == 1 and parsed["extra"] == "ok"


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, "recall body must be an object"),
        ({}, "recall query must be a non-empty string"),
        ({"query": ""}, "recall query must be a non-empty string"),
        ({"query": "x", "max_tokens": 0}, "max_tokens must be a positive integer"),
        ({"query": "x", "budget": "huge"}, "budget must be low, mid, or high"),
        ({"query": "x", "types": [1]}, "types must contain strings"),
        ({"query": "x", "tags": [1]}, "tags must contain strings"),
        ({"query": "x", "tags_match": 1}, "tags_match must be a string"),
        ({"query": "x", "trace": "yes"}, "trace must be a boolean"),
    ],
)
def test_recall_validation_errors(value: object, message: str) -> None:
    with pytest.raises(HttpError, match=message):
        validation.parse_recall_body(value)


def test_recall_validation_success() -> None:
    assert validation.parse_recall_body({"query": "hello", "max_tokens": 5, "trace": True}) == {
        "query": "hello",
        "max_tokens": 5,
        "trace": True,
    }


def test_dedupe_helpers_and_shapes() -> None:
    key = dedupe.request_dedupe_key("retain", "main", "x", {"a": 1})
    assert key == dedupe.request_dedupe_key("retain", "main", "x", {"a": 1})
    assert dedupe.security_event_dedupe_key("get", "/X/?q=1") == "GET:/x"
    assert dedupe.security_event_dedupe_key("POST", "") == "POST:/"
    cap = dedupe.SecurityEventIdentityCap()
    first = cap.resolve(None, "x")
    assert cap.resolve(None, "x") == first
    for i in range(63):
        cap.resolve("w", str(i))
    assert cap.resolve("overflow", "x") == "aggregate"
    assert dedupe.request_family_identity("other", "x", None, {}) is None
    a = dedupe.request_family_identity(
        "retain_request", "unknown_writer", "x", {"tags": ["B", "a"], "content": "  HELLO   world "}
    )
    b = dedupe.request_family_identity(
        "retain_request", "unknown_writer", "y", {"tags": ["a", "b"], "content": "hello world"}
    )
    assert a == b
    assert (
        dedupe.request_family_identity(
            "recall_request", "suspicious", None, {"query": None, "trace": True, "n": 1}
        )
        is not None
    )


def test_hindsight_bounds() -> None:
    cfg = HindsightLimitConfig(
        max_retain_items=1,
        max_retain_content_bytes=4,
        max_recall_query_bytes=3,
        max_recall_max_tokens=2,
    )
    limits = HindsightLimits(cfg, InMemoryRateLimiter())
    limits.assert_retain_bounds({"items": [{"content": "1234"}]})
    with pytest.raises(HttpError) as too_many:
        limits.assert_retain_bounds({"items": [{"content": "a"}, {"content": "b"}]})
    assert too_many.value.code == "retain_item_limit_exceeded"
    with pytest.raises(HttpError) as too_large:
        limits.assert_retain_bounds({"items": [{"content": "12345"}]})
    assert too_large.value.code == "retain_content_too_large"
    limits.assert_recall_bounds({"query": "123", "max_tokens": 2})
    with pytest.raises(HttpError) as query:
        limits.assert_recall_bounds({"query": "1234"})
    assert query.value.code == "recall_query_too_large"
    with pytest.raises(HttpError) as tokens:
        limits.assert_recall_bounds({"query": "x", "max_tokens": 3})
    assert tokens.value.code == "recall_max_tokens_exceeded"


@pytest.mark.asyncio
async def test_hindsight_quota_buckets_and_mapping() -> None:
    limiter = InMemoryRateLimiter()
    cfg = HindsightLimitConfig(
        retain_writer_max=1,
        retain_global_max=2,
        recall_writer_max=1,
        recall_global_max=2,
        rate_limit_window_ms=1500,
    )
    limits = HindsightLimits(cfg, limiter)
    await limits.consume_retain("a")
    with pytest.raises(HttpError) as exc:
        await limits.consume_retain("a")
    assert exc.value.code == "hindsight_rate_limited" and exc.value.headers == {"retry-after": "2"}
    await limits.consume_recall("a")

    class Broken:
        async def consume_many(self, buckets: object) -> None:
            raise HttpError(500, "x", "x")

    with pytest.raises(HttpError) as raw:
        await HindsightLimits(cfg, Broken()).consume_retain("a")
    assert raw.value.status == 500


@pytest.mark.asyncio
async def test_in_memory_sliding_window_expiry_and_disabled_buckets() -> None:
    limiter = InMemoryRateLimiter()
    await limiter.consume_many([("off", 0, 1), ("x", 1, 10)], at_ms=10)
    with pytest.raises(HttpError):
        await limiter.consume_many([("x", 1, 10)], at_ms=10)
    await limiter.consume_many([("x", 1, 10)], at_ms=20)


@pytest.mark.asyncio
async def test_in_memory_rate_limiter_count_distinct_expiry_and_lock() -> None:
    limiter = InMemoryRateLimiter()
    await limiter.consume_many_distinct(
        [("b", 1, 10), ("off", 0, 1)], [("s", "a", 1, 10), ("off", "x", 0, 1)], at_ms=10
    )
    with pytest.raises(HttpError):
        await limiter.consume_many([("b", 1, 10)], at_ms=10)
    with pytest.raises(HttpError):
        await limiter.consume_many_distinct([], [("s", "b", 1, 10)], at_ms=10)
    await limiter.consume_many_distinct([("b", 1, 10)], [("s", "b", 1, 10)], at_ms=20)

    async def operation(session: InMemoryRateLimiter) -> str:
        assert session is limiter
        return "ok"

    assert await limiter.with_identity_lock("id", operation) == "ok"


class FakeTx:
    def __init__(self, rows: list[dict[str, int] | None] | None = None) -> None:
        self.rows = list(rows or [])
        self.executed: list[tuple[str, tuple[object, ...] | None]] = []

    async def execute(self, sql: str, params: tuple[object, ...] | None = None) -> None:
        self.executed.append((sql, params))

    async def fetchone(
        self, sql: str, params: tuple[object, ...] | None = None
    ) -> dict[str, int] | None:
        self.executed.append((sql, params))
        return self.rows.pop(0) if self.rows else None


class TxContext:
    def __init__(self, tx: FakeTx) -> None:
        self.tx = tx

    async def __aenter__(self) -> FakeTx:
        return self.tx

    async def __aexit__(self, *args: object) -> None:
        return None


class FakeDatabase:
    def __init__(self, tx: FakeTx) -> None:
        self.tx = tx

    def transaction(self) -> TxContext:
        return TxContext(self.tx)


@pytest.mark.asyncio
async def test_postgres_rate_limiter_paths() -> None:
    tx = FakeTx([{"count": 0}, {"count": 0}, None, {"now_ms": 100}])
    session = _PostgresSession(tx)
    await session.consume_many_distinct(
        [("b", 2, 10), ("b", 2, 10), ("off", 0, 1)], [("s", "a", 2, 10)], at_ms=50
    )
    assert any("advisory_xact_lock" in sql for sql, _ in tx.executed)

    assert await _PostgresSession(FakeTx([{"now_ms": 123}]))._database_now_ms() == 123
    await _PostgresSession(FakeTx()).consume_many_distinct([], [])

    with pytest.raises(HttpError):
        await _PostgresSession(FakeTx([{"count": 1}])).consume_many_distinct(
            [("b", 1, 10)], [], at_ms=20
        )
    with pytest.raises(HttpError):
        await _PostgresSession(FakeTx([{"count": 1}, None])).consume_many_distinct(
            [], [("s", "new", 1, 10)], at_ms=20
        )

    tx2 = FakeTx()
    limiter = PostgresRateLimiter(FakeDatabase(tx2))
    await limiter.initialize()
    await limiter.consume_many([], at_ms=1)

    async def op(session2: object) -> str:
        assert isinstance(session2, _PostgresSession)
        return "locked"

    assert await limiter.with_identity_lock("id", op) == "locked"
