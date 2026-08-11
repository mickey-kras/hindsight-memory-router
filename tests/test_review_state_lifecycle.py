from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from memory_router.errors import HttpError
from memory_router.maintenance import cleanup_params
from memory_router.policy import RouterPolicy
from memory_router.repository import Capacity, QuarantineRepository

SIDE_EFFECT_STATES = ("review_side_effect_started", "review_side_effect_completed")


class TransactionDatabase:
    @asynccontextmanager
    async def transaction(self, **_: object):  # type: ignore[no-untyped-def]
        yield SimpleNamespace()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", SIDE_EFFECT_STATES)
async def test_recall_suppresses_review_side_effect_states(status: str) -> None:
    repository = SimpleNamespace(
        find_memory_state=AsyncMock(return_value={"status": status}),
    )
    store = SimpleNamespace(put=AsyncMock())
    policy = RouterPolicy(
        SimpleNamespace(writers={}),
        SimpleNamespace(),
        SimpleNamespace(),
        store,
        repository,
    )

    allowed = await policy._allow_recalled(
        "main",
        "http",
        "main",
        {"id": "m1", "text": "safe changed content"},
    )

    assert allowed is False
    store.put.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", SIDE_EFFECT_STATES)
async def test_requarantine_cannot_refresh_review_side_effect_states(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    repository = QuarantineRepository(cast(Any, TransactionDatabase()))
    find_existing = AsyncMock(return_value={"status": status})
    assert_capacity = AsyncMock()
    monkeypatch.setattr(repository, "_find_existing", find_existing)
    monkeypatch.setattr(repository, "_assert_capacity", assert_capacity)

    with pytest.raises(HttpError) as blocked:
        await repository.store(
            {"source_bank": "main", "source_memory_id": "m1"},
            Capacity(1, 1, 1),
            mode="memory",
            at="2026-08-10T00:00:00.000Z",
        )

    assert blocked.value.code == "quarantine_item_in_review"
    assert_capacity.assert_not_awaited()


def test_cleanup_all_excludes_review_side_effect_states() -> None:
    where, params = cleanup_params("all", None, None)

    assert params == []
    for status in SIDE_EFFECT_STATES:
        assert f"'{status}'" in where
