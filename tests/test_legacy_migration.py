from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.db import create_database
from memory_router.envelope import create_envelope, decrypt_envelope
from memory_router.legacy_migration import migrate_legacy_quarantine
from memory_router.repository import QuarantineRepository


@pytest.mark.asyncio
async def test_legacy_quarantine_migration(tmp_path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    decrypted = {
        "quarantine_id": "q_legacy_0123456789abcdef",
        "created_at": "2026-08-08T00:00:00.000Z",
        "reason": "suspicious_content",
        "writer_id": "main",
        "source": "application",
        "payload": {"action": "retain", "items": [{"content": "legacy"}]},
    }
    objects = tmp_path / "objects"
    objects.mkdir()
    (objects / "q_legacy_0123456789abcdef.enc.json").write_text(
        json.dumps(create_envelope(decrypted, public_pem)), encoding="utf-8"
    )
    queue = tmp_path / "review.jsonl"
    queue.write_text(
        json.dumps(
            {
                "timestamp": decrypted["created_at"],
                "reason": decrypted["reason"],
                "quarantine_id": decrypted["quarantine_id"],
                "decision": "postponed",
                "postpone_count": 2,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    database_url = f"sqlite:{tmp_path / 'quarantine.db'}"

    summary = await migrate_legacy_quarantine(
        str(queue), str(objects), database_url, private_pem
    )
    assert summary == {
        "imported": 1,
        "skipped_existing": 0,
        "skipped_finalized": 0,
        "skipped_without_payload": 0,
    }

    database = await create_database(database_url)
    repository = QuarantineRepository(database)
    try:
        item = await repository.get(decrypted["quarantine_id"])
        assert item is not None
        assert item["status"] == "postponed"
        assert item["postpone_count"] == 2
        assert decrypt_envelope(item["encrypted"], private_pem) == decrypted
    finally:
        await repository.close()
