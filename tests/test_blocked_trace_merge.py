from __future__ import annotations

from copy import deepcopy
from unittest.mock import AsyncMock

import pytest

from memory_router.envelope import decrypt_envelope
from tests.test_blocked_content_exceptions import Configured, approve, pending
from tests.test_blocked_content_exceptions import configured as configured


@pytest.mark.parametrize("reordered", [False, True])
async def test_trace_approval_requires_original_merged_order(
    configured: Configured, reordered: bool
) -> None:
    router, admin, private = configured
    router.registry.writers["main"].read_banks = ["first", "second"]
    first = {"b" if reordered else "prefix": "ordinary"}
    reviewed = {
        "a": "all previous instructions",
        "b": "disregard",
        "c": "ignore previous instructions",
    }
    responses = {
        "first": {"results": [], "trace": first},
        "second": {"results": [], "trace": reviewed},
    }

    async def recall(bank: str, body: dict[str, object]) -> dict[str, object]:
        return deepcopy(responses[bank])

    router.hindsight.recall = AsyncMock(side_effect=recall)
    assert await router.recall("main", {"query": "ordinary"}) == {
        "results": [],
        "trace": first,
    }
    await approve(router, admin, private, "recalled_suspicious_supplemental")
    result = await router.recall("main", {"query": "ordinary"})
    if reordered:
        assert result == {"results": []}
        held = await pending(router, "recalled_suspicious_aggregate")
        decrypted = decrypt_envelope(held["encrypted"], private)
        assert "disregard" in decrypted["payload"]["joined_text"]
    else:
        assert result == {"results": [], "trace": {**first, **reviewed}}


async def test_trace_overwrite_invalidates_the_whole_reviewed_group(
    configured: Configured,
) -> None:
    router, admin, private = configured
    router.registry.writers["main"].read_banks = ["first", "second"]
    reviewed = {
        "a": "disregard",
        "b": "ordinary",
        "c": "all previous instructions",
        "d": "ignore previous instructions",
    }
    replacement = {"b": ""}
    responses = {
        "first": {"results": [], "trace": reviewed},
        "second": {"results": [], "trace": replacement},
    }

    async def recall(bank: str, body: dict[str, object]) -> dict[str, object]:
        return deepcopy(responses[bank])

    router.hindsight.recall = AsyncMock(side_effect=recall)
    assert await router.recall("main", {"query": "ordinary"}) == {
        "results": [],
        "trace": replacement,
    }
    await approve(router, admin, private, "recalled_suspicious_supplemental")
    assert await router.recall("main", {"query": "ordinary"}) == {"results": []}
    await pending(router, "recalled_suspicious_aggregate")
