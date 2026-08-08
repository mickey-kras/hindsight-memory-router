from __future__ import annotations

import json

import pytest

from memory_router.auth import bearer_matches, is_admin_authorized, is_router_authorized
from memory_router.config import Settings, assert_no_private_key_environment, is_postgres_url
from memory_router.errors import HttpError, safe_error_body
from memory_router.registry import DEFAULT_REGISTRY, load_registry, validate_registry
from memory_router.validation import parse_recall_body, parse_retain_body


def test_default_settings_and_deployment_validation(capsys):
    settings = Settings.from_env({})
    assert settings.port == 8890
    assert settings.hindsight_base_url == "http://hindsight:8888"
    assert settings.registry_path is None
    assert settings.quarantine_database_url == "sqlite:./data/quarantine.db"
    assert settings.hindsight_limits.max_retain_items == 100
    assert settings.quarantine_limits.item_ttl_days == 30
    assert is_postgres_url("postgres://db")
    assert is_postgres_url("postgresql://db")
    assert not is_postgres_url("sqlite:x")

    with pytest.raises(ValueError, match="single or cluster"):
        Settings.from_env({"MEMORY_ROUTER_DEPLOYMENT_MODE": "oops"})
    with pytest.raises(ValueError, match="PostgreSQL"):
        Settings.from_env({"MEMORY_ROUTER_DEPLOYMENT_MODE": "cluster"})
    with pytest.raises(ValueError, match="EXTERNAL"):
        Settings.from_env(
            {
                "MEMORY_ROUTER_DEPLOYMENT_MODE": "cluster",
                "QUARANTINE_DATABASE_URL": "postgresql://db/x",
            }
        )
    Settings.from_env({"MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT": "true"})
    assert "external limiter" in capsys.readouterr().err


def test_settings_reject_invalid_values_and_private_key():
    with pytest.raises(ValueError, match="must be an integer"):
        Settings.from_env({"MEMORY_ROUTER_PORT": "NaN"})
    with pytest.raises(ValueError, match=">= 1"):
        Settings.from_env({"MEMORY_ROUTER_PORT": "0"})
    with pytest.raises(ValueError, match="true or false"):
        Settings.from_env({"MEMORY_ROUTER_ALLOW_ANONYMOUS": "maybe"})
    with pytest.raises(ValueError, match="must not be available"):
        assert_no_private_key_environment({"QUARANTINE_PRIVATE_KEY": "secret"})
    with pytest.raises(ValueError, match="must not be available"):
        Settings.from_env({"QUARANTINE_PRIVATE_KEY_FILE": "/tmp/k"})


def test_request_validation_preserves_contract():
    retain = parse_retain_body(
        {
            "items": [
                {
                    "content": "hello",
                    "context": None,
                    "document_id": "d",
                    "tags": ["x"],
                    "metadata": {"a": "b"},
                    "update_mode": "append",
                }
            ],
            "async": True,
            "document_tags": ["doc"],
            "future": "preserved",
        }
    )
    assert retain.model_dump_wire()["async"] is True
    assert retain.model_dump_wire()["future"] == "preserved"
    recall = parse_recall_body(
        {
            "query": "hello",
            "max_tokens": 4,
            "budget": "mid",
            "types": ["fact"],
            "tags": ["x"],
            "tags_match": "any",
            "trace": False,
            "future": 1,
        }
    )
    assert recall.query == "hello"
    assert recall.model_dump()["future"] == 1

    invalid_retain = [
        None,
        {},
        {"items": []},
        {"items": [1]},
        {"items": [{"content": " "}]},
        {"items": [{"content": "x", "context": 1}]},
        {"items": [{"content": "x", "document_id": 1}]},
        {"items": [{"content": "x", "timestamp": 1}]},
        {"items": [{"content": "x", "tags": [1]}]},
        {"items": [{"content": "x", "metadata": {"a": 1}}]},
        {"items": [{"content": "x", "update_mode": "bad"}]},
        {"items": [{"content": "x"}], "async": 1},
        {"items": [{"content": "x"}], "document_tags": [1]},
    ]
    for value in invalid_retain:
        with pytest.raises(HttpError) as exc:
            parse_retain_body(value)
        assert exc.value.code == "invalid_retain_body"

    invalid_recall = [
        None,
        {},
        {"query": ""},
        {"query": "x", "max_tokens": True},
        {"query": "x", "max_tokens": 0},
        {"query": "x", "budget": "huge"},
        {"query": "x", "types": [1]},
        {"query": "x", "tags": [1]},
        {"query": "x", "tags_match": 1},
        {"query": "x", "trace": 1},
    ]
    for value in invalid_recall:
        with pytest.raises(HttpError) as exc:
            parse_recall_body(value)
        assert exc.value.code == "invalid_recall_body"


def test_registry_defaults_and_validation(tmp_path):
    assert list(DEFAULT_REGISTRY.writers) == ["main"]
    assert DEFAULT_REGISTRY.writers["main"].source == "application"
    registry = validate_registry(
        {
            "writers": {
                "dev": {
                    "role": "developer",
                    "source": "application",
                    "write_bank": "dev",
                    "read_banks": ["main", "dev"],
                }
            },
            "defaults": {
                "unknown_writer_action": "review_queue",
                "suspicious_content_action": "review_queue",
            },
        }
    )
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry.model_dump()), encoding="utf-8")
    assert load_registry(str(path)).writers["dev"].write_bank == "dev"
    for mutation, match in [
        ({}, "writers"),
        ({"writers": {}, "defaults": {}}, "unknown_writer_action"),
        (
            {
                "writers": {"main": {"role": "x", "source": "x", "write_bank": "quarantine", "read_banks": []}},
                "defaults": {"unknown_writer_action": "review_queue", "suspicious_content_action": "review_queue"},
            },
            "cannot write quarantine",
        ),
        (
            {
                "writers": {"main": {"role": "x", "source": "x", "write_bank": "main", "read_banks": ["research"]}},
                "defaults": {"unknown_writer_action": "review_queue", "suspicious_content_action": "review_queue"},
            },
            "cannot read research",
        ),
    ]:
        with pytest.raises(ValueError, match=match):
            validate_registry(mutation)


def test_auth_scopes_and_error_mapping():
    assert bearer_matches("Bearer token", ["token"])
    assert not bearer_matches("Bearer tokenx", ["token"])
    assert not bearer_matches(None, ["token"])
    assert is_router_authorized("Bearer router", "router", False)
    assert not is_router_authorized(None, "router", False)
    assert is_router_authorized(None, None, True)
    assert is_admin_authorized("Bearer review", "read", legacy=None, read=None, review="review", cleanup=None)
    assert is_admin_authorized("Bearer cleanup", "cleanup", legacy=None, read=None, review=None, cleanup="cleanup")
    assert not is_admin_authorized("Bearer cleanup", "review", legacy=None, read=None, review="review", cleanup="cleanup")
    assert is_admin_authorized("Bearer root", "review", legacy="root", read=None, review=None, cleanup=None)

    error = HttpError(429, "limited", "slow", {"Retry-After": "60"})
    assert safe_error_body(error) == (429, {"error": "limited", "message": "slow"}, {"Retry-After": "60"})
    assert safe_error_body(RuntimeError())[0:2] == (500, {"error": "internal error"})


def _registry(writer_id="dev", **writer):
    rule = {"role":"developer","source":"application","write_bank":"dev","read_banks":["dev"]}
    rule.update(writer)
    return {
        "writers": {writer_id: rule},
        "defaults": {"unknown_writer_action":"review_queue","suspicious_content_action":"review_queue"},
    }


def test_registry_all_domain_validation_branches(tmp_path):
    assert load_registry().writers["main"].write_bank == "main"
    cases = [
        ([], "registry must be an object"),
        ({"writers":[],"defaults":{}}, "writers"),
        ({"writers":{},"defaults":[]}, "defaults"),
        ({"writers":{},"defaults":{"unknown_writer_action":"review_queue"}}, "suspicious_content_action"),
        (_registry(**{"role":""}), "missing role"),
        (_registry(**{"source":""}), "missing source"),
        (_registry(**{"write_bank":"wat"}), "invalid write_bank"),
        (_registry(**{"read_banks":"dev"}), "missing read_banks"),
        (_registry(**{"read_banks":["quarantine"]}), "cannot read quarantine"),
        (_registry(**{"read_banks":["wat"]}), "invalid read_bank"),
        (_registry(writer_id="", **{}), "writer id cannot be empty"),
        ({"writers":{"dev":1},"defaults":{"unknown_writer_action":"review_queue","suspicious_content_action":"review_queue"}}, "must be an object"),
        ({"writers":{"dev":{"role":"x","source":"x","write_bank":"dev"}},"defaults":{"unknown_writer_action":"review_queue","suspicious_content_action":"review_queue"}}, "missing read_banks"),
    ]
    for value, match in cases:
        with pytest.raises(ValueError, match=match):
            validate_registry(value)


def test_warn_auth_and_bool_numeric_variants(capsys):
    from memory_router.config import warn_auth

    anonymous = Settings.from_env({"MEMORY_ROUTER_ALLOW_ANONYMOUS":"1"})
    warn_auth(anonymous)
    text = capsys.readouterr().err
    assert "ALLOW_ANONYMOUS" in text and "admin read token" in text and "admin cleanup token" in text

    legacy = Settings.from_env({"MEMORY_ROUTER_TOKEN":"r","MEMORY_ROUTER_ADMIN_TOKEN":"root"})
    warn_auth(legacy)
    assert "legacy admin migration superuser" in capsys.readouterr().err

    configured = Settings.from_env({
        "MEMORY_ROUTER_TOKEN":"r",
        "MEMORY_ROUTER_ADMIN_REVIEW_TOKEN":"review",
        "MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN":"cleanup",
        "MEMORY_ROUTER_ALLOW_ANONYMOUS":"0",
    })
    warn_auth(configured)
    assert capsys.readouterr().err == ""
