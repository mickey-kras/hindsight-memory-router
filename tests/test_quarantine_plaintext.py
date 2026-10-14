from __future__ import annotations

import asyncio
import base64
import copy
import json
from dataclasses import replace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from memory_router.dedupe import request_dedupe_key
from memory_router.envelope import (
    _aad,
    canonical_decrypted,
    create_envelope,
    create_provider_envelope,
    estimate_envelope_size,
)
from memory_router.errors import HttpError
from memory_router.key_wrap import provider_envelope_metadata
from tests.test_quarantine_store import base_input, public_key, store_fixture
from tests.test_wrap_providers import StaticWrapProvider

_GOLDEN_PLAINTEXT = (
    '{"created_at":"2026-08-08T00:00:00.000Z",'
    '"payload":{"a":[true,null,0,1e-7,9007199254740991],'
    r'"é":"line\nquote\"",'
    '"😀":1,"\ue000":2},'
    '"quarantine_id":"q_20260808_0123456789abcdef","reason":"suspicious_content",'
    '"source":"приложение","writer_id":"mäin"}'
)
_GOLDEN_SHA256 = "f8384ee7a2b0441d764625f3e97ea76a9e9afc081d31c31d6ec550f104ea5b3e"


def _plaintext(envelope: dict[str, Any], provider: StaticWrapProvider) -> bytes:
    assert provider.dek is not None
    encryption = envelope["encryption"]
    return AESGCM(provider.dek).decrypt(
        base64.b64decode(encryption["iv_b64"]),
        base64.b64decode(envelope["ciphertext_b64"]) + base64.b64decode(encryption["tag_b64"]),
        _aad(envelope),
    )


async def test_public_envelope_helpers_preserve_canonical_plaintext_and_hash() -> None:
    value = json.loads(_GOLDEN_PLAINTEXT)
    value["payload"]["a"][2] = -0.0
    value["extra"] = {"excluded": True}
    assert canonical_decrypted(value) == _GOLDEN_PLAINTEXT
    assert create_envelope(value, public_key())["sha256"] == _GOLDEN_SHA256
    provider = StaticWrapProvider()
    envelope = await create_provider_envelope(value, provider)
    assert _plaintext(envelope, provider) == _GOLDEN_PLAINTEXT.encode("utf-8")
    assert envelope["sha256"] == _GOLDEN_SHA256
    assert "extra" not in envelope


async def test_store_preserves_canonical_plaintext_and_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, repository, _ = store_fixture()
    provider = StaticWrapProvider()
    store.wrap_provider = provider
    value = json.loads(_GOLDEN_PLAINTEXT)
    monkeypatch.setattr(store, "_resolve_id", lambda _: value["quarantine_id"])
    result = await store.put(
        base_input(
            payload=value["payload"],
            writerId=value["writer_id"],
            source=value["source"],
        )
    )
    saved = repository.store.await_args.args[0]
    evidence = repository.store.await_args.kwargs["incoming_evidence"]
    assert _plaintext(saved["encrypted"], provider) == _GOLDEN_PLAINTEXT.encode("utf-8")
    assert evidence.plaintext == _GOLDEN_PLAINTEXT
    assert result["sha256"] == saved["sha256"] == _GOLDEN_SHA256


async def test_request_family_normalization_does_not_replace_request_or_plaintext_identity() -> (
    None
):
    store, _, limiter = store_fixture()
    payloads = [
        {"tags": ["B", "a"], "content": "  HELLO   world "},
        {"tags": ["a", "b"], "content": "hello world"},
    ]
    results = [
        await store.put(
            base_input(
                payload=payload,
                dedupeKey=request_dedupe_key("retain_request", "main", "bank", payload),
            )
        )
        for payload in payloads
    ]
    assert limiter.session.distinct_calls[0] == limiter.session.distinct_calls[1]
    assert results[0]["quarantine_id"] != results[1]["quarantine_id"]
    assert results[0]["sha256"] != results[1]["sha256"]


async def test_security_identity_can_share_a_key_without_sharing_plaintext_hash() -> None:
    store, _, _ = store_fixture()
    results = [
        await store.put(base_input("security_event", dedupeKey="event", payload={"count": count}))
        for count in (1, 2)
    ]
    assert results[0]["quarantine_id"] == results[1]["quarantine_id"]
    assert results[0]["sha256"] != results[1]["sha256"]


@pytest.mark.parametrize(
    "payload",
    [
        {"key": (1, 2)},
        {"key": b"bytes"},
        {"key": {1, 2}},
        {1: "numeric key"},
        {"key": 2**53},
        {"key": float("nan")},
        {"key": float("inf")},
        {"key": float("-inf")},
        {"key": "\ud800"},
        {"key": object()},
    ],
)
async def test_invalid_plaintext_fails_before_quota_or_wrap(payload: object) -> None:
    store, repository, limiter = store_fixture()
    provider = StaticWrapProvider()
    provider.wrap = AsyncMock(wraps=provider.wrap)
    store.wrap_provider = provider
    input_ = base_input(dedupeKey="invalid", payload=payload)
    value = store._decrypted(input_, store._resolve_id(input_))
    with pytest.raises(ValueError, match="JSON values only"):
        canonical_decrypted(value)
    with pytest.raises(ValueError, match="JSON values only"):
        estimate_envelope_size(value, 256)
    with pytest.raises(ValueError, match="JSON values only"):
        create_envelope(value, "invalid public key")
    with pytest.raises(ValueError, match="JSON values only"):
        await create_provider_envelope(value, provider)
    with pytest.raises(ValueError, match="JSON values only"):
        await store.put(input_)
    provider.wrap.assert_not_awaited()
    repository.store.assert_not_awaited()
    assert not limiter.session.count_calls and not limiter.session.distinct_calls


@pytest.mark.parametrize("wrapped_key_bytes", [0, -1])
def test_size_helper_checks_wrapped_key_size_before_plaintext(wrapped_key_bytes: int) -> None:
    with pytest.raises(ValueError, match="wrapped key size must be positive"):
        estimate_envelope_size({}, wrapped_key_bytes)


@pytest.mark.parametrize("wrapped_bytes,bound", [(256, 256), (512, 512), (64, 512)])
async def test_provider_size_bound_is_applied_before_wrapping(
    wrapped_bytes: int, bound: int
) -> None:
    store, repository, limiter = store_fixture()
    provider = StaticWrapProvider(wrapped=b"w" * wrapped_bytes, name="k" * 64, version=123)
    provider.wrapped_key_bytes = bound
    provider.wrap = AsyncMock(wraps=provider.wrap)
    store.wrap_provider = provider
    input_ = base_input(dedupeKey="size", writerId="mäin", source="приложение")
    estimate = estimate_envelope_size(
        store._decrypted(input_, store._resolve_id(input_)),
        bound,
        key_wrap=provider.key_wrap,
        provider=provider_envelope_metadata(provider.envelope_provider()),
    )
    store.limits = replace(store.limits, max_item_bytes=estimate)
    await store.put(input_)
    envelope = repository.store.await_args.args[0]["encrypted"]
    actual = len(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    assert actual == estimate if wrapped_bytes == bound else actual < estimate
    provider.wrap.assert_awaited_once()
    store.limits = replace(store.limits, max_item_bytes=estimate - 1)
    with pytest.raises(HttpError) as oversized:
        await store.put(input_)
    assert oversized.value.code == "quarantine_item_too_large"
    provider.wrap.assert_awaited_once()
    repository.store.assert_awaited_once()
    assert len(limiter.session.distinct_calls) == 1


@pytest.mark.parametrize("phase", ["quota", "wrap"])
async def test_awaited_admission_preserves_preflight_payload_and_row_metadata(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    store, repository, limiter = store_fixture()
    provider = StaticWrapProvider()
    store.wrap_provider = provider
    input_ = base_input(
        dedupeKey="stable",
        sourceBank="bank",
        sourceMemoryId="memory",
        sourceContentSha256="content-sha",
        bankId="bank",
    )
    original = copy.deepcopy(input_)
    expected = canonical_decrypted(store._decrypted(original, store._resolve_id(original)))
    store.limits = replace(
        store.limits,
        max_item_bytes=estimate_envelope_size(
            json.loads(expected),
            provider.wrapped_key_bytes,
            key_wrap=provider.key_wrap,
            provider=provider_envelope_metadata(provider.envelope_provider()),
        ),
    )
    started = asyncio.Event()
    release = asyncio.Event()
    target = limiter if phase == "quota" else provider
    method = "consume_many_distinct" if phase == "quota" else "wrap"
    operation = getattr(target, method)

    async def blocked(*args: Any) -> Any:
        started.set()
        await release.wait()
        return await operation(*args)

    monkeypatch.setattr(target, method, blocked)
    write = asyncio.create_task(store.put(input_))
    try:
        await asyncio.wait_for(started.wait(), 2)
        input_["payload"]["items"][0]["content"] = "changed" * 1000
        input_.update(
            timestamp="2026-08-09T00:00:00.000Z",
            kind="recalled_memory",
            reason="unknown_writer",
            writerId="changed",
            source="changed",
            dedupeKey="changed",
            sourceBank="changed",
            sourceMemoryId="changed",
            sourceContentSha256="changed",
            bankId="changed",
        )
    finally:
        release.set()
        await write
    call = repository.store.await_args
    saved = call.args[0]
    assert _plaintext(saved["encrypted"], provider) == expected.encode("utf-8")
    assert call.kwargs["incoming_evidence"].plaintext == expected
    assert call.kwargs["at"] == original["timestamp"]
    assert call.kwargs["mode"] == "request"
    assert saved["created_at"] == saved["updated_at"] == original["timestamp"]
    assert saved["kind"] == original["kind"]
    assert saved["reason"] == saved["encrypted"]["reason"] == original["reason"]
    for row_field, input_field in (
        ("writer_id", "writerId"),
        ("source", "source"),
        ("dedupe_key", "dedupeKey"),
        ("source_bank", "sourceBank"),
        ("source_memory_id", "sourceMemoryId"),
        ("source_content_sha256", "sourceContentSha256"),
        ("bank_id", "bankId"),
    ):
        assert saved[row_field] == original[input_field]
