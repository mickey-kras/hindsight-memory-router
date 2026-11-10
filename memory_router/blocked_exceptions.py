from __future__ import annotations

import json
from contextvars import ContextVar
from functools import cache
from importlib.metadata import version
from pathlib import Path

from .canonical import canonical_json, sha256_hex
from .principals import PrincipalRegistry, PrincipalSession

AUTHORIZATION_CONTEXT: ContextVar[dict[str, object] | None] = ContextVar(
    "blocked_content_authorization", default=None
)


def authorization_context(
    session: PrincipalSession, registry: PrincipalRegistry
) -> dict[str, object]:
    return {
        "principal": session.principal_id,
        "source": session.source,
        "grants": [grant.model_dump(mode="json") for grant in session.grants],
        "banks": {name: bank.model_dump(mode="json") for name, bank in registry.banks.items()},
    }


def ordered_content_json(value: object) -> str:
    canonical_json(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def ordered_content_digest(value: object) -> str:
    return sha256_hex(ordered_content_json(value))


@cache
def scanner_policy_digest() -> str:
    package = Path(__file__).parent
    return sha256_hex(
        canonical_json(
            {
                "code": {
                    path.name: sha256_hex(path.read_text()) for path in sorted(package.glob("*.py"))
                },
                "confusables": sha256_hex((package / "confusables_ascii.json").read_text()),
                "guard_version": version("agent-memory-guard"),
            }
        )
    )
