from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from .db import create_database
from .envelope import create_envelope, decode_private_key, decrypt_envelope
from .repository import QuarantineRepository
from .review_repository import postpone

_QID = re.compile(r"^q_[0-9A-Za-z]+_[0-9a-f]{16}$")


async def migrate_legacy_quarantine(
    queue_path: str,
    object_directory: str,
    database_url: str,
    key_text: str,
) -> dict[str, int]:
    database = await create_database(database_url)
    repository = QuarantineRepository(database)
    try:
        return await import_legacy_quarantine(
            repository,
            Path(queue_path),
            Path(object_directory),
            key_text,
        )
    finally:
        await repository.close()


async def import_legacy_quarantine(
    repository: QuarantineRepository,
    queue_path: Path,
    object_directory: Path,
    key_text: str,
) -> dict[str, int]:
    key = decode_private_key(key_text)
    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    records = _parse_queue(queue_path.read_text(encoding="utf-8"))
    summary = {
        "imported": 0,
        "skipped_existing": 0,
        "skipped_finalized": 0,
        "skipped_without_payload": 0,
    }

    for record in records:
        if record["decision"] not in {"pending", "postponed"}:
            summary["skipped_finalized"] += 1
            continue
        quarantine_id = record.get("quarantine_id")
        if not isinstance(quarantine_id, str):
            summary["skipped_without_payload"] += 1
            continue
        if await repository.get(quarantine_id):
            summary["skipped_existing"] += 1
            continue

        envelope = json.loads(
            _object_path(object_directory, quarantine_id).read_text(encoding="utf-8")
        )
        decrypted = decrypt_envelope(envelope, key_text)
        if decrypted["quarantine_id"] != quarantine_id:
            raise ValueError(f"legacy queue/envelope mismatch for {quarantine_id}")
        encrypted = create_envelope(decrypted, public_key)
        item = {
            "quarantine_id": quarantine_id,
            "created_at": decrypted["created_at"],
            "updated_at": decrypted["created_at"],
            "kind": _legacy_kind(decrypted["payload"]),
            "reason": decrypted["reason"],
            "writer_id": decrypted.get("writer_id"),
            "source": decrypted.get("source"),
            "source_bank": None,
            "source_memory_id": None,
            "source_content_sha256": None,
            "dedupe_key": None,
            "sha256": encrypted["sha256"],
            "encrypted": encrypted,
            "status": "pending",
            "postpone_count": 0,
            "requarantine_count": 0,
            "expires_at": None,
        }
        async with repository.db.transaction() as tx:
            await repository._insert(tx, item)

        postpone_count = int(record.get("postpone_count") or 0)
        if record["decision"] == "postponed":
            postpone_count = max(1, postpone_count)
        postponed_at = str(record.get("decided_at") or record["timestamp"])
        for _ in range(max(0, postpone_count)):
            await postpone(repository, quarantine_id, postponed_at)
        summary["imported"] += 1

    return summary


def _parse_queue(raw: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"legacy queue line {line_number} must be an object")
        if value.get("decision") not in {
            "pending",
            "postponed",
            "rejected",
            "promoted",
        }:
            raise ValueError(f"legacy queue line {line_number} has an invalid decision")
        if not isinstance(value.get("timestamp"), str) or not value["timestamp"]:
            raise ValueError(f"legacy queue line {line_number} has no timestamp")
        if not isinstance(value.get("reason"), str) or not value["reason"]:
            raise ValueError(f"legacy queue line {line_number} has no reason")
        records.append(value)
    return records


def _legacy_kind(payload: Any) -> str:
    if not isinstance(payload, dict):
        raise ValueError("legacy quarantine payload must be an object")
    if payload.get("action") == "retain":
        return "retain_request"
    if payload.get("action") == "recall":
        return "recall_request"
    raise ValueError("legacy quarantine payload action is unsupported")


def _object_path(directory: Path, quarantine_id: str) -> Path:
    if not _QID.fullmatch(quarantine_id):
        raise ValueError("invalid legacy quarantine_id")
    base = directory.resolve()
    path = (base / f"{quarantine_id}.enc.json").resolve()
    if path.parent != base:
        raise ValueError("invalid legacy quarantine object path")
    return path
