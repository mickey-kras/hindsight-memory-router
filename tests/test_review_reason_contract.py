from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, get_args

import pytest

from memory_router.admin import AdminActor, QuarantineAdminService
from memory_router.db import SqliteDatabase, initialize_schema
from memory_router.envelope import QuarantineReason, parse_decrypted, parse_envelope
from memory_router.errors import HttpError
from memory_router.maintenance import cleanup, preview_cleanup
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore
from memory_router.rate_limit import InMemoryRateLimiter
from memory_router.repository import QuarantineRepository
from tests.fakes import FakeHindsight, FakeLimits, registry
from tests.test_quarantine_store import base_input, public_key

EXPECTED_REASONS = {
    "unknown_writer",
    "suspicious_content",
    "suspicious_query",
    "recalled_suspicious_memory",
    "recalled_suspicious_supplemental",
    "denied_endpoint",
    "auth_failed",
    "openclaw_suspicious_request",
    "openclaw_unknown_writer",
    "openclaw_suspicious_provider_response",
}
ACTOR = AdminActor(token_scope="cleanup")  # noqa: S106 - label, not a secret


def _spec() -> dict[str, Any]:
    return json.loads(Path("openapi/openapi.json").read_text())


def test_review_reason_enum_matches_python_and_ui_without_duplicates() -> None:
    schemas = _spec()["components"]["schemas"]
    documented = schemas["ReviewReason"]["enum"]
    python_reasons = get_args(QuarantineReason)
    ui_array = re.search(
        r"^export const REASONS = (\[.*?\]) as const;$",
        Path("ui/src/lib/types.ts").read_text(),
        re.MULTILINE | re.DOTALL,
    )
    assert ui_array is not None
    ui_reasons = json.loads(re.sub(r",\s*\]$", "]", ui_array[1]))
    for reasons in (documented, python_reasons, ui_reasons):
        assert set(reasons) == EXPECTED_REASONS
        assert len(reasons) == len(set(reasons))
    assert schemas["ReviewReason"]["type"] == "string"


def test_reason_fields_and_queue_response_reference_the_shared_contract() -> None:
    spec = _spec()
    schemas = spec["components"]["schemas"]
    reference = {"$ref": "#/components/schemas/ReviewReason"}
    for name in (
        "QuarantinedResponse",
        "QuarantineItemSummary",
        "EncryptedQuarantineEnvelope",
        "DecryptedQuarantineObject",
    ):
        assert schemas[name]["properties"]["reason"] == reference
    assert schemas["CleanupRequest"]["properties"]["reasons"]["items"] == reference
    queue = spec["paths"]["/admin/quarantine/queue"]["get"]
    assert queue["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/QuarantineQueueResponse"
    }
    assert schemas["QuarantineQueueResponse"]["properties"]["items"]["items"] == {
        "$ref": "#/components/schemas/QuarantineItemSummary"
    }


@pytest.fixture
async def populated_queue(
    tmp_path: Path,
) -> AsyncIterator[tuple[QuarantineRepository, QuarantineAdminService]]:
    database = SqliteDatabase(str(tmp_path / "reasons.db"))
    await database.initialize()
    await initialize_schema(database)
    repository = QuarantineRepository(database)
    store = QuarantineStore(public_key(), repository, QuarantineLimits(), InMemoryRateLimiter())
    try:
        for reason in sorted(EXPECTED_REASONS):
            await store.put(base_input(reason=reason))
        yield (
            repository,
            QuarantineAdminService(repository, FakeHindsight(), registry(), FakeLimits()),
        )
    finally:
        await database.close()


async def test_real_queue_and_envelope_inputs_use_documented_reasons(
    populated_queue: tuple[QuarantineRepository, QuarantineAdminService],
) -> None:
    repository, service = populated_queue
    documented = _spec()["components"]["schemas"]["ReviewReason"]["enum"]
    queue = await service.list_queue(100, 0)
    assert queue["total"] == len(EXPECTED_REASONS)
    assert {item["reason"] for item in queue["items"]} == set(documented)
    for item in queue["items"]:
        assert item["reason"] in documented
        stored = await repository.get(item["quarantine_id"])
        assert stored is not None
        envelope = stored["encrypted"]
        assert parse_envelope(envelope)["reason"] == item["reason"]
        decrypted = {
            "quarantine_id": item["quarantine_id"],
            "created_at": item["created_at"],
            "reason": item["reason"],
            "payload": {"items": [{"content": "x"}]},
        }
        assert parse_decrypted(decrypted) == decrypted
        for invalid in ("other", "", item["reason"].upper(), item["reason"] + " "):
            assert invalid not in documented
            with pytest.raises(ValueError, match="invalid quarantine reason|reason must be"):
                parse_decrypted({**decrypted, "reason": invalid})
            with pytest.raises(ValueError, match="invalid quarantine reason"):
                parse_envelope({**envelope, "reason": invalid})


async def test_cleanup_preview_and_execution_accept_each_documented_reason(
    populated_queue: tuple[QuarantineRepository, QuarantineAdminService],
) -> None:
    repository, service = populated_queue
    for reason in sorted(EXPECTED_REASONS):
        preview = await service.cleanup({"reasons": [reason]}, ACTOR)
        assert preview["dry_run"] is True and preview["count"] == 1
        assert preview["encrypted_bytes"] > 0
        result = await service.cleanup(
            {"reasons": [reason], "dry_run": False, "expected_count": preview["count"]}, ACTOR
        )
        assert result == {**preview, "dry_run": False}
        assert (await service.cleanup({"reasons": [reason]}, ACTOR))["count"] == 0
    assert (await service.list_queue(100, 0)) == {"items": [], "total": 0}
    async with repository.db.transaction() as tx:
        events = await tx.fetchall(
            "SELECT details FROM quarantine_events WHERE event_type='cleanup'"
        )
    assert {json.loads(event["details"])["filter"]["reasons"][0] for event in events} == (
        EXPECTED_REASONS
    )


@pytest.mark.parametrize(
    "reasons",
    [
        ["other"],
        ["auth_failed", "other"],
        ["auth_failed", 1],
        ["auth_failed", {"reason": "auth_failed"}],
        ["auth_failed "],
        ["AUTH_FAILED"],
    ],
)
async def test_invalid_cleanup_reasons_reject_before_item_or_event_mutation(
    populated_queue: tuple[QuarantineRepository, QuarantineAdminService], reasons: list[Any]
) -> None:
    repository, service = populated_queue
    async with repository.db.transaction() as tx:
        before_items = await tx.fetchall("SELECT * FROM quarantine_items ORDER BY quarantine_id")
        before_events = await tx.fetchall("SELECT * FROM quarantine_events ORDER BY event_id")
    for operation in (
        preview_cleanup(repository, "pending", reasons, None),
        cleanup(repository, "all", reasons, None, 10, "now"),
        service.cleanup({"reasons": reasons, "dry_run": True}, ACTOR),
        service.cleanup({"reasons": reasons, "dry_run": False, "expected_count": 10}, ACTOR),
    ):
        with pytest.raises(HttpError) as invalid:
            await operation
        assert invalid.value.status == 400
        assert invalid.value.code == "invalid_cleanup"
    async with repository.db.transaction() as tx:
        assert (
            await tx.fetchall("SELECT * FROM quarantine_items ORDER BY quarantine_id")
            == before_items
        )
        assert (
            await tx.fetchall("SELECT * FROM quarantine_events ORDER BY event_id") == before_events
        )
