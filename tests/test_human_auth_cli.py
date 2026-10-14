from __future__ import annotations

import json
from pathlib import Path

import pytest

from memory_router.cli import human_auth
from memory_router.db import create_database
from memory_router.human_auth_config import generation_for, load_human_config
from memory_router.human_auth_store import HumanAuthStore
from memory_router.principals import load_principal_registry


@pytest.fixture
def configured_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str, str]:
    registry = tmp_path / "principals.json"
    config = tmp_path / "human.json"
    registry.write_text(
        json.dumps(
            {
                "principals": {
                    "human-test": {
                        "source": "human",
                        "grants": [{"bank": "alpha", "scopes": ["memory.recall"]}],
                    }
                }
            }
        )
    )
    config.write_text(
        json.dumps(
            {
                "router_url": "https://router.example",
                "issuer": "https://issuer.example",
                "client_id": "native",
                "subjects": {"subject": "human-test"},
            }
        )
    )
    database_url = f"sqlite:{tmp_path / 'cli.db'}"
    monkeypatch.setenv("MEMORY_ROUTER_PRINCIPALS", str(registry))
    monkeypatch.setenv("MEMORY_ROUTER_HUMAN_AUTH", str(config))
    monkeypatch.setenv("QUARANTINE_DATABASE_URL", database_url)
    monkeypatch.delenv("MEMORY_ROUTER_TOKEN", raising=False)
    return str(config), str(registry), database_url


async def test_activation_and_revoke(configured_cli: tuple[str, str, str]) -> None:
    config_path, registry_path, database_url = configured_cli
    await human_auth._operate("activate", None)
    database = await create_database(database_url)
    try:
        registry = load_principal_registry(registry_path)
        config = load_human_config(config_path, registry)
        store = HumanAuthStore(database, generation_for(config, registry))
        issued = await store.issue(principal_id="human-test", grants=())
        await human_auth._operate("revoke", issued.key_id)
        assert await store.authenticate(issued.key_id, issued.token.split("_")[2]) is None
        issued = await store.issue(principal_id="human-test", grants=())
        await human_auth._operate("activate", None)
        assert await store.authenticate(issued.key_id, issued.token.split("_")[2]) is None
    finally:
        await database.close()


def test_run_activation(
    configured_cli: tuple[str, str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert human_auth.run(["activate"]) == 0
    assert capsys.readouterr().out == "Human authentication policy activated.\n"


def test_no_secret_error_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def fail(action: str, key_id: str | None) -> None:
        raise RuntimeError("database://user:private-password@host")

    monkeypatch.setattr(human_auth, "_operate", fail)
    assert human_auth.run(["activate"]) == 1
    output = capsys.readouterr()
    assert "private-password" not in output.err
    assert "failed" in output.err


@pytest.mark.parametrize("value", ["mrh_" + "a" * 32 + "_" + "b" * 64, "A" * 32, "bad"])
def test_key_id_validation(value: str) -> None:
    with pytest.raises(SystemExit) as error:
        human_auth.run(["revoke", "--key-id", value])
    assert error.value.code == 2
