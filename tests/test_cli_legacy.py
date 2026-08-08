from __future__ import annotations

import io
import json

import pytest

from memory_router.cli import bootstrap_quarantine_keys as bootstrap_cli
from memory_router.cli import decrypt_quarantine as decrypt_cli
from memory_router.cli import migrate_legacy_quarantine as migrate_cli
from memory_router.quarantine.crypto import DecryptedQuarantineObject, create_envelope
from memory_router.quarantine.db import SqliteDatabase
from memory_router.quarantine.legacy_migration import (
    _legacy_object_path,
    _parse_queue,
    migrate_legacy_quarantine,
)
from memory_router.quarantine.repository import QuarantineRepository
from tests.helpers import keypair


def test_bootstrap_keys_create_existing_repair_and_refuse(tmp_path, monkeypatch, capsys):
    pub = tmp_path / "pub" / "key.pem"
    priv = tmp_path / "private" / "key.pem"
    assert bootstrap_cli.bootstrap_quarantine_keys(str(pub), str(priv), 2048) == "created"
    assert (priv.stat().st_mode & 0o777) == 0o600
    assert bootstrap_cli.bootstrap_quarantine_keys(str(pub), str(priv), 2048) == "existing"
    pub.unlink()
    assert bootstrap_cli.bootstrap_quarantine_keys(str(pub), str(priv), 2048) == "repaired-public-key"

    orphan = tmp_path / "orphan.pem"
    orphan.write_text(pub.read_text())
    with pytest.raises(ValueError, match="public key exists without"):
        bootstrap_cli.bootstrap_quarantine_keys(str(orphan), str(tmp_path / "missing-private.pem"), 2048)

    # Mismatched pair is rejected.
    other_pub, _ = keypair()
    pub.write_text(other_pub)
    with pytest.raises(ValueError, match="do not match"):
        bootstrap_cli.bootstrap_quarantine_keys(str(pub), str(priv), 2048)

    monkeypatch.setattr(bootstrap_cli, "bootstrap_quarantine_keys", lambda *_: "created")
    assert bootstrap_cli.main(["--public-key", "p", "--private-key", "s"]) == 0
    assert "created" in capsys.readouterr().out
    assert bootstrap_cli.main([]) == 1
    assert "failed" in capsys.readouterr().err


def test_decrypt_cli_preserves_original_and_warns_on_controls(tmp_path, monkeypatch, capsys):
    public, private = keypair()
    decrypted = DecryptedQuarantineObject(
        quarantine_id="q_test_0123456789abcdef",
        created_at="2026-08-07T00:00:00.000Z",
        reason="suspicious_content",
        writer_id="main",
        source="application",
        payload={"content":"line\nzero\u200b", "k\u200b":"v"},
    )
    envelope = create_envelope(decrypted, public)
    path = tmp_path / "response.json"
    path.write_text(json.dumps({"encrypted": envelope}))
    monkeypatch.setattr("sys.stdin", io.StringIO(private))
    assert decrypt_cli.main([str(path)]) == 0
    captured = capsys.readouterr()
    assert "zero\\\\u200B" in captured.err
    assert "zero\\u200b" in captured.out or "zero​" in captured.out
    assert decrypt_cli.extract_envelope(envelope)["version"] == 1
    changed, visible = decrypt_cli.escaped_review_value(["a\r\tb", "\U000E0001", 1])
    assert changed and visible[0] == "a\\r\\tb" and "\\u{" in visible[1]
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert decrypt_cli.main([str(path)]) == 1
    assert decrypt_cli.main([]) == 1


@pytest.mark.asyncio
async def test_legacy_migration_imports_and_is_idempotent(tmp_path):
    public, private = keypair()
    objects = tmp_path / "objects"
    objects.mkdir()
    qid1 = "q_old_0123456789abcdef"
    qid2 = "q_old_fedcba9876543210"
    for qid, action in [(qid1, "retain"), (qid2, "recall")]:
        decrypted = DecryptedQuarantineObject(
            quarantine_id=qid,
            created_at="2026-01-01T00:00:00.000Z",
            reason="suspicious_content",
            writer_id="main",
            source="application",
            payload={"action": action, "writer_id":"main", "body": {"items":[{"content":"x"}]}} if action == "retain" else {"action":"recall","writer_id":"main","body":{"query":"x"}},
        )
        (objects / f"{qid}.enc.json").write_text(json.dumps(create_envelope(decrypted, public)))
    queue = tmp_path / "queue.jsonl"
    queue.write_text("\n".join([
        json.dumps({"timestamp":"2026-01-01T00:00:00.000Z","reason":"suspicious_content","decision":"pending","quarantine_id":qid1}),
        json.dumps({"timestamp":"2026-01-01T00:00:00.000Z","reason":"suspicious_query","decision":"postponed","quarantine_id":qid2,"postpone_count":2}),
        json.dumps({"timestamp":"2026-01-01T00:00:00.000Z","reason":"suspicious_content","decision":"rejected","quarantine_id":"q_nope_1111111111111111"}),
        json.dumps({"timestamp":"2026-01-01T00:00:00.000Z","reason":"suspicious_content","decision":"pending"}),
    ]))
    dburl = f"sqlite:{tmp_path / 'migration.db'}"
    summary = await migrate_legacy_quarantine(str(queue), str(objects), dburl, private)
    assert summary == {"imported":2,"skipped_existing":0,"skipped_finalized":1,"skipped_without_payload":1}
    again = await migrate_legacy_quarantine(str(queue), str(objects), dburl, private)
    assert again["skipped_existing"] == 2

    repo = QuarantineRepository(SqliteDatabase(str(tmp_path / "migration.db")))
    await repo.initialize()
    assert (await repo.get(qid1)).kind == "retain_request"  # type: ignore[union-attr]
    assert (await repo.get(qid2)).postpone_count == 2  # type: ignore[union-attr]
    await repo.close()


def test_legacy_helpers_reject_malformed(tmp_path):
    assert _parse_queue("\n") == []
    for raw in [
        "[]",
        '{"decision":"wat","timestamp":"x","reason":"r"}',
        '{"decision":"pending","reason":"r"}',
        '{"decision":"pending","timestamp":"x"}',
    ]:
        with pytest.raises(ValueError):
            _parse_queue(raw)
    with pytest.raises(ValueError):
        _legacy_object_path(str(tmp_path), "../bad")


def test_migrate_cli_success_and_errors(monkeypatch, capsys):
    async def fake(*_args):
        return {"imported":1,"skipped_existing":0,"skipped_finalized":0,"skipped_without_payload":0}
    monkeypatch.setattr(migrate_cli, "migrate_legacy_quarantine", fake)
    monkeypatch.setattr("sys.stdin", io.StringIO("private"))
    assert migrate_cli.main(["--queue","q","--objects","o","--database","sqlite:x"]) == 0
    assert '"imported":1' in capsys.readouterr().out
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert migrate_cli.main(["--queue","q","--objects","o"]) == 1
    assert migrate_cli.main([]) == 1
