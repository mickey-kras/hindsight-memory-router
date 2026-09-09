from __future__ import annotations

import pytest
from pydantic import ValidationError

from memory_router.config import DEFAULT_REGISTRY
from memory_router.models import RecallResponse
from memory_router.policy import RouterPolicy
from tests.fakes import (
    FakeHindsight,
    FakeLimits,
    FakeRepository,
    FakeStore,
)


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
    store = FakeStore(quarantine_id="q_test_0123456789abcdef")
    policy = RouterPolicy(
        DEFAULT_REGISTRY.model_copy(deep=True),
        FakeHindsight(response=upstream),
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
        FakeHindsight(response=upstream),
        FakeLimits(),
        FakeStore(quarantine_id="q_test_0123456789abcdef"),
        FakeRepository(),
    )

    assert await policy.recall("main", {"query": "status"}) == upstream


def test_recall_result_only_validates_id_and_text() -> None:
    parsed = RecallResponse.model_validate(
        {"results": [{"id": "1", "text": "ok", "type": 7, "metadata": "opaque"}]}
    )
    dumped = parsed.model_dump()
    assert dumped["results"][0]["type"] == 7
    assert dumped["results"][0]["metadata"] == "opaque"
    with pytest.raises(ValidationError):
        RecallResponse.model_validate({"results": [{"id": 1, "text": "ok"}]})
