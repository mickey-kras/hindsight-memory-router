from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from ..config import DEFAULT_DATABASE_URL
from .crypto import create_envelope, decode_private_key, decrypt_envelope
from .db import create_database
from .repository import NewItem, QuarantineRepository


async def migrate_legacy_quarantine(
    queue_path: str,
    object_directory: str,
    database_url: str,
    private_key_input: str,
) -> dict[str, int]:
    database = create_database(database_url or DEFAULT_DATABASE_URL)
    repository = QuarantineRepository(database)
    await repository.initialize()
    try:
        private_key = decode_private_key(private_key_input)
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        records = _parse_queue(Path(queue_path).read_text(encoding="utf-8"))
        summary = {
            "imported": 0,
            "skipped_existing": 0,
            "skipped_finalized": 0,
            "skipped_without_payload": 0,
        }
        for record in records:
            decision = record["decision"]
            if decision not in {"pending", "postponed"}:
                summary["skipped_finalized"] += 1
                continue
            qid = record.get("quarantine_id")
            if not isinstance(qid, str) or not qid:
                summary["skipped_without_payload"] += 1
                continue
            if await repository.get(qid) is not None:
                summary["skipped_existing"] += 1
                continue
            envelope_path = _legacy_object_path(object_directory, qid)
            decrypted = decrypt_envelope(
                json.loads(envelope_path.read_text(encoding="utf-8")), private_key_input
            )
            if decrypted.quarantine_id != qid:
                raise ValueError(f"legacy queue/envelope mismatch for {qid}")
            encrypted = create_envelope(decrypted, public_key)
            payload = decrypted.payload
            if not isinstance(payload, dict) or payload.get("action") not in {"retain", "recall"}:
                raise ValueError("legacy quarantine payload action is unsupported")
            kind = "retain_request" if payload["action"] == "retain" else "recall_request"
            item = NewItem(
                quarantine_id=qid,
                created_at=decrypted.created_at,
                updated_at=decrypted.created_at,
                kind=kind,
                reason=decrypted.reason,
                writer_id=decrypted.writer_id,
                source=decrypted.source,
                source_bank=None,
                source_memory_id=None,
                source_content_sha256=None,
                dedupe_key=None,
                sha256=encrypted["sha256"],
                encrypted=encrypted,
                status="pending",
                postpone_count=0,
                requarantine_count=0,
                expires_at=None,
            )
            await repository.insert(item)
            count = int(record.get("postpone_count", 0) or 0)
            if decision == "postponed":
                count = max(1, count or 1)
            else:
                count = max(0, count)
            at = str(record.get("decided_at") or record["timestamp"])
            for _ in range(count):
                await repository.postpone(qid, at)
            summary["imported"] += 1
        return summary
    finally:
        await repository.close()


def _parse_queue(raw: str) -> list[dict[str, Any]]:
    records = []
    for index, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"legacy queue line {index} must be an object")
        if value.get("decision") not in {"pending", "postponed", "rejected", "promoted"}:
            raise ValueError(f"legacy queue line {index} has an invalid decision")
        if not isinstance(value.get("timestamp"), str) or not value["timestamp"]:
            raise ValueError(f"legacy queue line {index} has no timestamp")
        if not isinstance(value.get("reason"), str) or not value["reason"]:
            raise ValueError(f"legacy queue line {index} has no reason")
        records.append(value)
    return records


def _legacy_object_path(directory: str, qid: str) -> Path:
    import re

    if not re.fullmatch(r"q_[0-9A-Za-z]+_[0-9a-f]{16}", qid):
        raise ValueError("invalid legacy quarantine_id")
    base = Path(directory).resolve()
    path = (base / f"{qid}.enc.json").resolve()
    if path.parent != base:
        raise ValueError("invalid legacy quarantine object path")
    return path
