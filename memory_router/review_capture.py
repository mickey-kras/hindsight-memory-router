from __future__ import annotations

from typing import Any

from .blocked_exceptions import ordered_content_digest
from .canonical import sha256_hex
from .security import _walk_strings

_CREDENTIAL_FIELDS = frozenset(
    {
        "authorization",
        "proxyauthorization",
        "apikey",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "password",
        "passwd",
        "secret",
        "clientsecret",
        "credentials",
        "cookie",
        "setcookie",
        "privatekey",
    }
)


def contains_credentials(value: Any, upstream_key: str | None) -> bool:
    for _, text, is_key in _walk_strings(value, "response"):
        if upstream_key and upstream_key in text:
            return True
        if (
            is_key
            and "".join(character for character in text.lower() if character.isalnum())
            in _CREDENTIAL_FIELDS
        ):
            return True
    return False


def joined_response_text(response: dict[str, Any]) -> str:
    return " ".join(
        text
        for _, text, is_key in _walk_strings(response, "recalled_response", include_numbers=True)
        if not is_key
    )


def context_digest(value: Any) -> str:
    try:
        return ordered_content_digest(value)
    except (ValueError, RecursionError):
        serialized = repr(value)
    return sha256_hex(serialized)
