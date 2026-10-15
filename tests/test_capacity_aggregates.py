from __future__ import annotations

import runpy
from itertools import product
from pathlib import Path

import pytest

from memory_router.db import create_database
from memory_router.repository import (
    _CAPACITY_TOTALS_SQL,
    _PENDING_SCOPE_PREFIX,
    Capacity,
    QuarantineRepository,
    _scoped_pending_count,
)
from tests.test_repository import item

AT = "2026-01-01T00:00:00.000Z"
OLD_TOTALS_SQL = """SELECT
    COALESCE(SUM(CASE WHEN status IN ('pending','postponed') AND NOT(expires_at IS NOT NULL AND expires_at<=?) THEN 1 ELSE 0 END),0) pending_count,
    COALESCE(SUM(CASE WHEN status IN ('pending','postponed') AND expires_at IS NOT NULL AND expires_at<=? THEN 0 ELSE encrypted_bytes END),0) encrypted_bytes,
    COALESCE(SUM(CASE WHEN kind='security_event' THEN 1 ELSE 0 END),0) security_event_count
    FROM quarantine_items"""


@pytest.mark.asyncio
async def test_capacity_aggregate_parity_and_large_history_plans(tmp_path: Path) -> None:
    db = await create_database(f"sqlite:{tmp_path / 'capacity.db'}")
    repository = QuarantineRepository(db)
    try:
        async with db.transaction() as tx:
            # Review history grows independently of both admission limits.
            await tx.execute(
                """WITH RECURSIVE history(n) AS (
                    SELECT 1 UNION ALL SELECT n+1 FROM history WHERE n<20000
                ) INSERT INTO quarantine_items (
                    quarantine_id,created_at,updated_at,kind,reason,sha256,status,
                    encrypted_bytes,source_bank,source_memory_id
                ) SELECT 'history-' || CAST(n AS TEXT),?,?,
                    'recalled_memory','suspicious_content','abc',
                    CASE WHEN n%2=0 THEN 'reviewed_allowed' ELSE 'reviewed_blocked' END,
                    0,'history-bank',CAST(n AS TEXT) FROM history""",
                (AT, AT),
            )
            statuses = (
                "pending",
                "postponed",
                "review_in_progress",
                "review_side_effect_started",
                "review_side_effect_completed",
                "reviewed_allowed",
                "reviewed_blocked",
            )
            scopes = (
                ("alice", "suspicious_content", "retain_request"),
                ("invented", "unknown_writer", "retain_request"),
                (None, "auth_failed", "security_event"),
                (None, "suspicious_content", "recall_request"),
            )
            for index, (status, expires, scope, size) in enumerate(
                product(statuses, (None, AT, "2027-01-01T00:00:00.000Z"), scopes, (0, 7))
            ):
                writer, reason, kind = scope
                value = {
                    **item(
                        str(index), writer=writer, reason=reason, status=status, expires=expires
                    ),
                    "kind": kind,
                    "bank_id": "alpha",
                }
                await repository.insert_item(tx, value)
                await tx.execute(
                    "UPDATE quarantine_items SET encrypted_bytes=? WHERE quarantine_id=?",
                    (size, str(index)),
                )
            for at in ("2025-01-01T00:00:00.000Z", AT, "2028-01-01T00:00:00.000Z"):
                assert await tx.fetchone(_CAPACITY_TOTALS_SQL, (at, at)) == await tx.fetchone(
                    OLD_TOTALS_SQL, (at, at)
                )
                for writer, reason, kind in scopes:
                    candidate = {"writer_id": writer, "reason": reason, "kind": kind}
                    conditions, params = (
                        ("reason='unknown_writer'", ())
                        if reason == "unknown_writer"
                        else ("reason <> 'unknown_writer' AND writer_id=?", (writer,))
                        if writer is not None
                        else (
                            "reason <> 'unknown_writer' AND writer_id IS NULL AND kind=?",
                            (kind,),
                        )
                    )
                    old = await tx.fetchone(
                        "SELECT COUNT(*) count FROM quarantine_items WHERE "  # noqa: S608
                        "status IN ('pending','postponed') AND "
                        "NOT(expires_at IS NOT NULL AND expires_at<=?) AND " + conditions,
                        (at, *params),
                    )
                    assert await _scoped_pending_count(tx, candidate, at) == old["count"]

            for analyzed in (False, True):
                if analyzed:
                    await tx.execute("ANALYZE")
                plans = await tx.fetchall("EXPLAIN QUERY PLAN " + _CAPACITY_TOTALS_SQL, (AT, AT))
                details = "\n".join(str(row["detail"]) for row in plans)
                assert "idx_quarantine_capacity_pending" in details, details
                assert "idx_quarantine_capacity_bytes" in details, details
                assert "idx_quarantine_capacity_security" in details, details
                for condition, params, index_name in (
                    ("bank_id=?", ("alpha",), "bank"),
                    ("reason='unknown_writer'", (), "unknown"),
                    ("reason <> 'unknown_writer' AND writer_id=?", ("alice",), "writer"),
                    (
                        "reason <> 'unknown_writer' AND writer_id IS NULL AND kind=?",
                        ("recall_request",),
                        "family",
                    ),
                ):
                    plan = await tx.fetchall(
                        "EXPLAIN QUERY PLAN " + _PENDING_SCOPE_PREFIX + condition, (AT, *params)
                    )
                    assert any(
                        f"idx_quarantine_capacity_{index_name}" in row["detail"] for row in plan
                    ), plan
                    assert all(row["detail"] != "SCAN quarantine_items" for row in plan), plan

        # Admission and lookup preserve approval/block decisions after the history scan.
        await repository.store(
            item("new", writer="fresh"), Capacity(1000, 1, 100000), mode="id", at=AT
        )
        assert (await repository.find_memory_state("history-bank", "2"))[
            "status"
        ] == "reviewed_allowed"
        assert (await repository.find_memory_state("history-bank", "1"))[
            "status"
        ] == "reviewed_blocked"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_capacity_aggregates_empty_table(tmp_path: Path) -> None:
    db = await create_database(f"sqlite:{tmp_path / 'empty.db'}")
    try:
        async with db.transaction() as tx:
            assert await tx.fetchone(_CAPACITY_TOTALS_SQL, (AT, AT)) == {
                "pending_count": 0,
                "encrypted_bytes": 0,
                "security_event_count": 0,
            }
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_capacity_smoke_across_sqlite_replicas(tmp_path: Path) -> None:
    helper = runpy.run_path("tests/integration/security-event-capacity.py")
    await helper["verify_capacity"](f"sqlite:{tmp_path / 'replicas.db'}")
