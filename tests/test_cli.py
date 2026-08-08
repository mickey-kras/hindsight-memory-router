from __future__ import annotations

import io
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
