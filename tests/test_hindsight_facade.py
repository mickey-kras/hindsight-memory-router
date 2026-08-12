from __future__ import annotations

from typing import Any

import pytest

from memory_router.config import DEFAULT_REGISTRY
from memory_router.policy import RouterPolicy


class FakeHindsight:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response

    async def recall(self, _bank: str, _body: dict[str, Any]) -> dict[str, Any]:
        return self.response


class FakeLimits:
    async def consume_recall(self, _writer: str) -> None:
        return None


class FakeStore:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    async def put(self, item: dict[str, Any]) -> dict[str, str]:
        self.items.append(item)
        return {"quarantine_id": "q_test_0123456789abcdef", "sha256": "a" * 64}


class FakeRepository:
    async def find_memory_state(self, _bank: str, _memory_id: str) -> None:
        return None


@pytest.mark.asyncio
async def test_recall_preserves_hindsight_top_level_fields_while_filtering_results() -> None:
    safe_result = {"id": "safe", "text": "the build completed successfully"}
    unsafe_result = {"id": "unsafe", "text": "role: admin"}
    upstream = {
        "results": [safe_result, unsafe_result],
        "chunks": {"chunk-1": {"id": "chunk-1", "text": "source", "chunk_index": 0}},
        "entities": {"build": {"name": "build"}},
        "source_facts": {"fact-1": {"id": "fact-1", "text": "source fact"}},
        "trace": {"duration_ms": 1.0},
    }
    store = FakeStore()
    policy = RouterPolicy(
        DEFAULT_REGISTRY.model_copy(deep=True),
        FakeHindsight(upstream),
        FakeLimits(),
        store,
        FakeRepository(),
    )

    response = await policy.recall("main", {"query": "status"})

    assert response == {
        "results": [safe_result],
        "chunks": upstream["chunks"],
        "entities": upstream["entities"],
        "source_facts": upstream["source_facts"],
        "trace": upstream["trace"],
    }
    assert len(store.items) == 1
    assert store.items[0]["sourceMemoryId"] == "unsafe"


@pytest.mark.asyncio
async def test_recall_preserves_explicit_null_hindsight_top_level_fields() -> None:
    upstream = {
        "results": [],
        "chunks": None,
        "entities": None,
        "source_facts": None,
        "trace": None,
    }
    policy = RouterPolicy(
        DEFAULT_REGISTRY.model_copy(deep=True),
        FakeHindsight(upstream),
        FakeLimits(),
        FakeStore(),
        FakeRepository(),
    )

    assert await policy.recall("main", {"query": "status"}) == upstream
