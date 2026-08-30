from __future__ import annotations

import io
import json
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import memory_router.cli.migrate_legacy_quarantine as migrate_cli
from memory_router.cli.decrypt_quarantine import run
from memory_router.envelope import create_envelope


def test_decrypt_quarantine_cli(tmp_path, monkeypatch, capsys) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    decrypted = {
        "quarantine_id": "q_test_0123456789abcdef",
        "created_at": "2026-08-08T00:00:00.000Z",
        "reason": "suspicious_content",
        "writer_id": "main",
        "source": "application",
        "payload": {"action": "retain", "items": [{"content": "review me"}]},
    }
    response = tmp_path / "response.json"
    response.write_text(json.dumps({"encrypted": create_envelope(decrypted, public_pem)}))
    monkeypatch.setattr(sys, "stdin", io.StringIO(private_pem))

    assert run(str(response)) == 0
    assert json.loads(capsys.readouterr().out) == decrypted


def test_decrypt_quarantine_cli_requires_stdin_key(tmp_path, monkeypatch, capsys) -> None:
    response = tmp_path / "response.json"
    response.write_text("{}")
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))

    assert run(str(response)) == 1
    assert "required on stdin" in capsys.readouterr().err


def test_migrate_legacy_quarantine_cli(monkeypatch, capsys) -> None:
    async def fake_migrate(*args: str) -> dict[str, int]:
        assert args == ("queue.jsonl", "objects", "sqlite:test.db", "key")
        return {"imported": 1}

    monkeypatch.setattr(migrate_cli, "migrate_legacy_quarantine", fake_migrate)
    monkeypatch.setattr(sys, "stdin", io.StringIO("key\n"))

    assert (
        migrate_cli.run(
            ["--queue", "queue.jsonl", "--objects", "objects", "--database", "sqlite:test.db"]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"imported": 1}


def test_migrate_legacy_quarantine_cli_requires_stdin_key(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))

    assert migrate_cli.run(["--queue", "queue.jsonl", "--objects", "objects"]) == 1
    assert "required on stdin" in capsys.readouterr().err


def test_migrate_legacy_quarantine_cli_rejects_sqlite_in_cluster(monkeypatch, capsys) -> None:
    monkeypatch.setenv("MEMORY_ROUTER_DEPLOYMENT_MODE", "cluster")
    monkeypatch.setenv("MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT", "true")
    monkeypatch.setattr(sys, "stdin", io.StringIO("key"))

    assert (
        migrate_cli.run(
            ["--queue", "queue.jsonl", "--objects", "objects", "--database", "sqlite:test.db"]
        )
        == 1
    )
    assert "cluster deployment requires PostgreSQL" in capsys.readouterr().err


def test_migrate_legacy_quarantine_main(monkeypatch) -> None:
    monkeypatch.setattr(migrate_cli, "run", lambda: 7)

    with pytest.raises(SystemExit) as exited:
        migrate_cli.main()
    assert exited.value.code == 7
