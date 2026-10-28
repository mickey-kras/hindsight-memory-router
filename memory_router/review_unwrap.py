"""Trusted review-tool unwrapping. Not imported or configured by the router runtime."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import import_module
from importlib.metadata import entry_points
from typing import Any, Protocol, cast

from .envelope import (
    DEFAULT_KEY_WRAP,
    ENVELOPE_WRAPPED_FIELD,
    KEY_WRAP_TOKEN_RE,
    decrypt_unwrapped_envelope,
    parse_envelope,
)


@dataclass(frozen=True, slots=True)
class ReviewProviderId:
    key_wrap: str
    name: str | None = None
    version: int | None = None


class ReviewUnwrapProvider(Protocol):
    identity: ReviewProviderId

    def unwrap(self, wrapped_dek: bytes, envelope: Mapping[str, Any]) -> bytes: ...


class ReviewProviderRegistry:
    def __init__(self, providers: Sequence[ReviewUnwrapProvider]) -> None:
        self._providers: dict[ReviewProviderId, ReviewUnwrapProvider] = {}
        for provider in providers:
            identity = provider.identity
            if (
                not isinstance(identity.key_wrap, str)
                or not KEY_WRAP_TOKEN_RE.fullmatch(identity.key_wrap)
                or (identity.name is None) != (identity.version is None)
                or (
                    identity.name is not None
                    and (
                        not isinstance(identity.name, str)
                        or not KEY_WRAP_TOKEN_RE.fullmatch(identity.name)
                        or not isinstance(identity.version, int)
                        or isinstance(identity.version, bool)
                        or identity.version < 1
                    )
                )
                or (identity.name is None and identity.key_wrap != DEFAULT_KEY_WRAP)
            ):
                raise ValueError("invalid review provider identity")
            if identity in self._providers:
                raise ValueError("duplicate review provider identity")
            self._providers[identity] = provider

    def decrypt(self, value: Any) -> dict[str, Any]:
        envelope = parse_envelope(value)
        encryption = envelope["encryption"]
        provider_info = encryption.get("provider")
        identity = ReviewProviderId(
            encryption["key_wrap"],
            provider_info["name"] if provider_info is not None else None,
            provider_info["version"] if provider_info is not None else None,
        )
        provider = self._providers.get(identity)
        if provider is None:
            raise ValueError("no matching review unwrap provider")
        wrapped = base64.b64decode(encryption[ENVELOPE_WRAPPED_FIELD], validate=True)
        dek = provider.unwrap(wrapped, envelope)
        if not isinstance(dek, bytes) or len(dek) != 32:
            raise ValueError("invalid decrypted quarantine key length")
        return decrypt_unwrapped_envelope(envelope, dek)


class Pkcs11RsaOaepProvider:
    """RSA-OAEP-SHA256 with a token-held private key; PIN/touch remain token-governed."""

    identity = ReviewProviderId(DEFAULT_KEY_WRAP)

    def __init__(self, module: str, token_label: str, key_label: str, pin: str) -> None:
        if not all((module, token_label, key_label, pin)):
            raise ValueError("PKCS#11 module, token, key label and PIN are required")
        self._module = module
        self._token_label = token_label
        self._key_label = key_label
        self._pin = pin

    def unwrap(self, wrapped_dek: bytes, envelope: Mapping[str, Any]) -> bytes:
        if "provider" in envelope["encryption"]:
            raise ValueError("PKCS#11 adapter only supports native RSA envelopes")
        # Load the optional python-pkcs11 distribution only in the reviewer process.
        pkcs11 = import_module("pkcs11")
        mgf = import_module("pkcs11.mechanisms").MGF

        token = pkcs11.lib(self._module).get_token(token_label=self._token_label)
        with token.open(user_pin=self._pin) as session:
            key = session.get_key(
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                key_type=pkcs11.KeyType.RSA,
                label=self._key_label,
            )
            return cast(
                bytes,
                key.decrypt(
                    wrapped_dek,
                    mechanism=pkcs11.Mechanism.RSA_PKCS_OAEP,
                    mechanism_param=(pkcs11.Mechanism.SHA256, mgf.SHA256, None),
                ),
            )


def load_review_provider(name: str) -> ReviewUnwrapProvider:
    """Load only an explicitly selected, independently installed review plugin."""
    matches = [
        entry
        for entry in entry_points(group="hindsight_memory_router.review_unwrap")
        if entry.name == name
    ]
    if len(matches) != 1:
        raise ValueError("review provider entry point is missing or ambiguous")
    provider = matches[0].load()()
    if not isinstance(getattr(provider, "identity", None), ReviewProviderId) or not callable(
        getattr(provider, "unwrap", None)
    ):
        raise ValueError("invalid external review provider")
    return cast(ReviewUnwrapProvider, provider)
