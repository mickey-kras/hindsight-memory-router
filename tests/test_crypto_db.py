from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from memory_router.canonical import canonical_json, sha256_hex
from memory_router.db import create_database
from memory_router.envelope import canonical_decrypted, create_envelope, decrypt_envelope


def keypair() -> tuple[str, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return public_pem, private_pem


def decrypted() -> dict[str, object]:
    return {
        "quarantine_id": "q_20260808_0123456789abcdef",
        "created_at": "2026-08-08T05:00:00.000Z",
        "reason": "suspicious_content",
        "writer_id": "main",
        "source": "openclaw",
        "payload": {"z": 1, "a": [True, "text"]},
    }


def test_canonical_json_is_stable_across_key_order() -> None:
    assert canonical_json({"z": 1, "a": 2}) == '{"a":2,"z":1}'
    assert canonical_json({"a": -0.0}) == '{"a":0}'


def test_envelope_round_trip_preserves_existing_format() -> None:
    public, private = keypair()
    envelope = create_envelope(decrypted(), public)
    assert envelope["version"] == 1
    assert envelope["encryption"]["algorithm"] == "AES-256-GCM"
    assert envelope["encryption"]["key_wrap"] == "RSA-OAEP-SHA256"
    assert envelope["encryption"]["aad"] == "metadata-v1"
    assert len(base64.b64decode(envelope["encryption"]["iv_b64"])) == 12
    assert len(base64.b64decode(envelope["encryption"]["tag_b64"])) == 16
    assert decrypt_envelope(envelope, private) == decrypted()


def test_authenticated_metadata_tampering_fails() -> None:
    public, private = keypair()
    envelope = create_envelope(decrypted(), public)
    envelope["reason"] = "unknown_writer"
    with pytest.raises(InvalidTag):
        decrypt_envelope(envelope, private)


def test_legacy_no_aad_envelope_still_decrypts() -> None:
    public_pem, private_pem = keypair()
    value = decrypted()
    plaintext = canonical_decrypted(value).encode()
    data_key = AESGCM.generate_key(bit_length=256)
    iv = bytes(range(12))
    public = serialization.load_pem_public_key(public_pem.encode())
    wrapped = public.encrypt(
        data_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    encrypted = AESGCM(data_key).encrypt(iv, plaintext, None)
    envelope = {
        "version": 1,
        "quarantine_id": value["quarantine_id"],
        "created_at": value["created_at"],
        "reason": value["reason"],
        "writer_id": value["writer_id"],
        "source": value["source"],
        "sha256": sha256_hex(plaintext.decode()),
        "encryption": {
            "algorithm": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            "wrapped_key_b64": base64.b64encode(wrapped).decode(),
            "iv_b64": base64.b64encode(iv).decode(),
            "tag_b64": base64.b64encode(encrypted[-16:]).decode(),
        },
        "ciphertext_b64": base64.b64encode(encrypted[:-16]).decode(),
    }
    assert decrypt_envelope(envelope, private_pem) == value


@pytest.mark.asyncio
async def test_existing_sqlite_schema_is_migrated_in_place(tmp_path: Path) -> None:
    database_path = tmp_path / "quarantine.db"
    connection = sqlite3.connect(database_path)
    connection.executescript(
        """
        CREATE TABLE quarantine_items (
          quarantine_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          kind TEXT NOT NULL, reason TEXT NOT NULL, writer_id TEXT, source TEXT,
          source_bank TEXT, source_memory_id TEXT, source_content_sha256 TEXT,
          sha256 TEXT NOT NULL, encrypted_envelope TEXT, encrypted_bytes INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL, postpone_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE quarantine_events (
          event_id TEXT PRIMARY KEY, quarantine_id TEXT NOT NULL, occurred_at TEXT NOT NULL,
          event_type TEXT NOT NULL, details TEXT NOT NULL
        );
        """
    )
    connection.execute(
        "INSERT INTO quarantine_items VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "q_existing_0123456789abcdef",
            "2026-08-01T00:00:00.000Z",
            "2026-08-01T00:00:00.000Z",
            "retain_request",
            "suspicious_content",
            "main",
            "openclaw",
            None,
            None,
            None,
            "a" * 64,
            json.dumps({"version": 1}),
            13,
            "pending",
            0,
        ),
    )
    connection.commit()
    connection.close()

    database = await create_database(f"sqlite:{database_path}")
    try:
        async with database.transaction() as tx:
            columns = await tx.fetchall("SELECT name FROM pragma_table_info('quarantine_items')")
            existing = await tx.fetchone(
                "SELECT quarantine_id,status FROM quarantine_items WHERE quarantine_id=?",
                ("q_existing_0123456789abcdef",),
            )
        names = {row["name"] for row in columns}
        assert {"dedupe_key", "requarantine_count", "expires_at"} <= names
        assert existing == {
            "quarantine_id": "q_existing_0123456789abcdef",
            "status": "pending",
        }
    finally:
        await database.close()
