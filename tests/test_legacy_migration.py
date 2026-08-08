from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.db import create_database
from memory_router.envelope import create_envelope, decrypt_envelope
from memory_router.legacy_migration import (
    _legacy_kind,
    _object_path,
    _parse_queue,
    import_legacy_quarantine,
    migrate_legacy_quarantine,
)
from memory_router.repository import QuarantineRepository


@pytest.mark.asyncio
async def test_legacy_quarantine_migration(tmp_path) -> None:
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

    summary = await migrate_legacy_quarantine(str(queue), str(objects), database_url, private_pem)
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


def test_legacy_queue_validation_and_helpers(tmp_path) -> None:
    with pytest.raises(ValueError, match="must be an object"):
        _parse_queue("[]")
    with pytest.raises(ValueError, match="invalid decision"):
        _parse_queue('{"timestamp":"now","reason":"x","decision":"bad"}')
    with pytest.raises(ValueError, match="no timestamp"):
        _parse_queue('{"reason":"x","decision":"pending"}')
    with pytest.raises(ValueError, match="no reason"):
        _parse_queue('{"timestamp":"now","decision":"pending"}')

    with pytest.raises(ValueError, match="must be an object"):
        _legacy_kind("bad")
    assert _legacy_kind({"action": "retain"}) == "retain_request"
    assert _legacy_kind({"action": "recall"}) == "recall_request"
    with pytest.raises(ValueError, match="unsupported"):
        _legacy_kind({"action": "other"})

    with pytest.raises(ValueError, match="invalid legacy quarantine_id"):
        _object_path(tmp_path, "../bad")


@pytest.mark.asyncio
async def test_legacy_quarantine_migration_skips_non_importable_records(tmp_path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    queue = tmp_path / "review.jsonl"
    queue.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-08-08T00:00:00.000Z",
                        "reason": "done",
                        "quarantine_id": "q_final_0123456789abcdef",
                        "decision": "rejected",
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-08-08T00:00:00.000Z",
                        "reason": "missing_payload",
                        "decision": "pending",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    database = await create_database(f"sqlite:{tmp_path / 'quarantine.db'}")
    repository = QuarantineRepository(database)
    try:
        summary = await import_legacy_quarantine(repository, queue, tmp_path / "objects", private_pem)
        assert summary == {
            "imported": 0,
            "skipped_existing": 0,
            "skipped_finalized": 1,
            "skipped_without_payload": 1,
        }
    finally:
        await repository.close()
