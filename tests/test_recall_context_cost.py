from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from memory_router import policy as policy_module
from tests.fakes import FakeHindsight
from tests.test_policy import policy


@pytest.mark.parametrize("bank_count", [8, 16, 32])
async def test_source_evidence_is_walked_once_per_bank(bank_count: int) -> None:
    router, _, _, _ = policy(FakeHindsight())
    banks = [f"bank-{position}" for position in range(bank_count)]
    router.registry.writers["main"].read_banks = banks
    responses: list[dict[str, object]] = [
        {
            "results": [],
            "chunks": {},
            "entities": {},
            "source_facts": {},
            "trace": {},
            "opaque_provider_metadata": "x" * 262_144,
        }
        for _ in banks
    ]
    router.hindsight.recall = AsyncMock(side_effect=responses)
    request = {"query": "ordinary"}
    with (
        patch("memory_router.policy._audit_digest", wraps=policy_module._audit_digest) as digest,
        patch(
            "memory_router.policy.contains_credentials", wraps=policy_module.contains_credentials
        ) as credentials,
    ):
        result = await router.recall("main", request)
    assert result == {"results": [], "chunks": {}, "entities": {}, "source_facts": {}, "trace": {}}
    assert sum(call.args[0] is request for call in digest.call_args_list) == 1
    for response in responses:
        assert sum(call.args[0] is response for call in digest.call_args_list) == 1
        assert sum(call.args[0] is response for call in credentials.call_args_list) == 1
