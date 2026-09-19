from __future__ import annotations

import json
import logging

import pytest

from memory_router.logging import log_event
from memory_router.logging_contract import sanitize_fields
from memory_router.repository import insert_event


def test_admin_action_audit_fields_follow_bounded_vocabularies() -> None:
    fields = sanitize_fields(
        {
            "action": "approve",
            "admin_token_scope": "review",
            "quarantine_id": "q_item_0123456789abcdef",
        }
    )
    assert fields["action"] == "approve"
    assert fields["admin_token_scope"] == "review"  # noqa: S105 - label, not a secret
    assert fields["quarantine_id"] == "q_item_0123456789abcdef"
    assert "action" not in sanitize_fields({"action": "drop-everything"})
    assert "admin_token_scope" not in sanitize_fields({"admin_token_scope": "Bearer secret"})
    assert "quarantine_id" not in sanitize_fields({"quarantine_id": "not a quarantine id"})


def test_admin_action_events_are_never_throttled(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("memory_router.test")
    caplog.set_level(logging.INFO, logger="memory_router.test")
    for _ in range(2):
        log_event(
            logger,
            "info",
            "admin_action",
            route_class="admin",
            action="cleanup",
            admin_token_scope="cleanup",  # noqa: S106 - label, not a secret
        )
    assert [record.msg for record in caplog.records].count("admin_action") == 2


class _CapturingTx:
    def __init__(self) -> None:
        self.statements: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, sql: str, params: tuple[object, ...]) -> None:
        self.statements.append((sql, params))


@pytest.mark.asyncio
async def test_insert_event_merges_actor_into_details() -> None:
    tx = _CapturingTx()
    await insert_event(  # type: ignore[arg-type]
        tx, "q_a_0123456789abcdef", "rejected", "now", {"reason": "x"}, actor="review"
    )
    await insert_event(tx, "q_b_0123456789abcdef", "rejected", "now", {"reason": "y"})  # type: ignore[arg-type]

    assert json.loads(str(tx.statements[0][1][4])) == {"reason": "x", "actor": "review"}
    assert json.loads(str(tx.statements[1][1][4])) == {"reason": "y"}
