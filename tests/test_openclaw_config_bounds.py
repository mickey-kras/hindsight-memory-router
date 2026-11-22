from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from memory_router.errors import HttpError
from memory_router.facade_routes import facade_route
from memory_router.openclaw import OpenClawFacade


def _policy() -> SimpleNamespace:
    return SimpleNamespace(
        registry=SimpleNamespace(
            writers={
                "openclaw": SimpleNamespace(
                    write_bank="physical-main", read_banks=["physical-main"]
                )
            }
        ),
        hindsight=SimpleNamespace(openclaw_request=AsyncMock()),
        limits=SimpleNamespace(consume_recall=AsyncMock(), consume_retain=AsyncMock()),
        capture_blocked_content=AsyncMock(),
        blocked_content_allowed=AsyncMock(return_value=False),
        quarantine_security_event=AsyncMock(),
    )


@pytest.mark.parametrize(
    "key", ["knowledge_banks", "KNOWLEDGE_BANKS", "HINDSIGHT_API_KNOWLEDGE_BANKS"]
)
@pytest.mark.asyncio
async def test_config_patch_rejects_cross_bank_references_before_quota_or_hindsight(
    key: str,
) -> None:
    policy = _policy()

    with pytest.raises(HttpError) as blocked:
        await OpenClawFacade(policy).forward(
            route=facade_route("PATCH", "config"),
            writer_id="openclaw",
            params={},
            body={"updates": {key: ["physical-other"]}},
        )

    assert blocked.value.status == 403
    assert blocked.value.code == "cross_bank_config_denied"
    policy.hindsight.openclaw_request.assert_not_awaited()
    policy.limits.consume_retain.assert_not_awaited()
