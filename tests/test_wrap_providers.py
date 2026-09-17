from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pytest_httpx import HTTPXMock

from memory_router import config
from memory_router.envelope import (
    _aad,
    create_envelope,
    create_provider_envelope,
    decrypt_envelope,
    estimate_envelope_size,
    parse_envelope,
)
from memory_router.errors import HttpError
from memory_router.key_wrap import (
    RsaOaepWrapProvider,
    SidecarWrapProvider,
    WrapProviderInfo,
    WrapSidecarError,
    provider_envelope_metadata,
)
from memory_router.quarantine_store import QuarantineLimits, QuarantineStore


def _keypair() -> tuple[str, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return public_pem, private_pem


def _decrypted(**extra: object) -> dict[str, object]:
    value: dict[str, object] = {
        "quarantine_id": "q_20260808_0123456789abcdef",
        "created_at": "2026-08-08T12:00:00.000Z",
        "reason": "suspicious_content",
        "payload": {"content": "x"},
    }
    value.update(extra)
    return value


class StaticWrapProvider:
    def __init__(self, wrapped: bytes = b"w" * 64, name: str = "test-kms", version: int = 3):
        self.key_wrap = "WRAP-TEST"
        self.wrapped_key_bytes = len(wrapped)
        self._wrapped = wrapped
        self._info = WrapProviderInfo(name, version)
        self.dek: bytes | None = None

    def envelope_provider(self) -> WrapProviderInfo:
        return self._info

    async def wrap(self, dek: bytes) -> bytes:
        self.dek = dek
        return self._wrapped

    async def close(self) -> None:
        return None


async def test_rsa_default_provider_envelope_matches_legacy_envelope_shape_and_decrypts() -> None:
    public_pem, private_pem = _keypair()
    provider = RsaOaepWrapProvider(public_pem)

    legacy = create_envelope(_decrypted(), public_pem)
    via_provider = await create_provider_envelope(_decrypted(), provider)

    assert set(via_provider) == set(legacy)
    assert via_provider["version"] == 1
    assert set(via_provider["encryption"]) == set(legacy["encryption"])
    assert "provider" not in via_provider["encryption"]
    assert via_provider["encryption"]["key_wrap"] == "RSA-OAEP-SHA256"
    assert _aad(via_provider).replace(
        via_provider["encryption"]["wrapped_key_b64"].encode(), b""
    ).replace(via_provider["encryption"]["iv_b64"].encode(), b"") == _aad(legacy).replace(
        legacy["encryption"]["wrapped_key_b64"].encode(), b""
    ).replace(legacy["encryption"]["iv_b64"].encode(), b"")
    assert decrypt_envelope(via_provider, private_pem)["payload"] == {"content": "x"}


async def test_provider_envelope_carries_provider_metadata_inside_aad() -> None:
    provider = StaticWrapProvider()
    envelope = await create_provider_envelope(_decrypted(), provider)

    assert envelope["encryption"]["key_wrap"] == "WRAP-TEST"
    assert envelope["encryption"]["provider"] == {"name": "test-kms", "version": 3}
    parsed = parse_envelope(envelope)
    assert parsed["encryption"]["provider"] == {"name": "test-kms", "version": 3}

    aad = json.loads(_aad(envelope))
    assert aad["encryption"]["provider"] == {"name": "test-kms", "version": 3}
    tampered = json.loads(json.dumps(envelope))
    tampered["encryption"]["provider"] = {"name": "test-kms", "version": 4}
    assert _aad(tampered) != _aad(envelope)


async def test_provider_envelope_never_falls_back_to_rsa_unwrap() -> None:
    public_pem, private_pem = _keypair()
    rsa_provider = RsaOaepWrapProvider(public_pem)
    wrapped = await rsa_provider.wrap(b"k" * 32)
    provider = StaticWrapProvider(wrapped=wrapped)
    envelope = await create_provider_envelope(_decrypted(), provider)

    with pytest.raises(ValueError, match="unsupported quarantine key wrap provider"):
        decrypt_envelope(envelope, private_pem)


def test_parse_envelope_rejects_unknown_wrap_and_malformed_provider() -> None:
    public_pem, _ = _keypair()
    envelope = create_envelope(_decrypted(), public_pem)

    unknown_wrap = json.loads(json.dumps(envelope))
    unknown_wrap["encryption"]["key_wrap"] = "RSA-OAEP-SHA512"
    with pytest.raises(ValueError, match="unsupported quarantine key wrapping algorithm"):
        parse_envelope(unknown_wrap)

    for provider in (
        {"name": "kms"},
        {"version": 1},
        {"name": "", "version": 1},
        {"name": "kms", "version": 0},
        {"name": "kms", "version": "1"},
        {"name": "kms", "version": True},
        {"name": "kms", "version": 1, "extra": "x"},
        "kms",
    ):
        tampered = json.loads(json.dumps(envelope))
        tampered["encryption"]["provider"] = provider
        with pytest.raises(ValueError, match="invalid quarantine key wrap provider"):
            parse_envelope(tampered)

    bad_wrap = json.loads(json.dumps(envelope))
    bad_wrap["encryption"]["key_wrap"] = "not a wrap!"
    bad_wrap["encryption"]["provider"] = {"name": "kms", "version": 1}
    with pytest.raises(ValueError, match="unsupported quarantine key wrapping algorithm"):
        parse_envelope(bad_wrap)


async def test_estimate_envelope_size_accounts_for_provider_metadata() -> None:
    public_pem, _ = _keypair()
    provider = StaticWrapProvider()
    info = provider.envelope_provider()

    default_estimate = estimate_envelope_size(_decrypted(), 256)
    provider_estimate = estimate_envelope_size(
        _decrypted(),
        provider.wrapped_key_bytes,
        key_wrap=provider.key_wrap,
        provider=provider_envelope_metadata(info),
    )
    assert provider_estimate != default_estimate

    envelope = await create_provider_envelope(_decrypted(), provider)
    actual = len(json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    assert provider_estimate == actual

    legacy = create_envelope(_decrypted(), public_pem)
    legacy_actual = len(
        json.dumps(legacy, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    assert estimate_envelope_size(_decrypted(), 256) == legacy_actual


async def test_sidecar_wrap_sends_dek_and_returns_wrapped_key(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://wrap.example/wrap",
        json={"wrapped_key_b64": base64.b64encode(b"z" * 128).decode("ascii")},
    )
    provider = SidecarWrapProvider(
        "https://wrap.example", "secret-token", 1_000, "acme-kms", 2, 256
    )
    try:
        wrapped = await provider.wrap(b"d" * 32)
    finally:
        await provider.close()

    assert wrapped == b"z" * 128
    request = httpx_mock.get_request()
    assert request is not None
    assert request.headers["authorization"] == "Bearer secret-token"
    assert json.loads(request.content) == {"dek_b64": base64.b64encode(b"d" * 32).decode("ascii")}


async def test_sidecar_wrap_fails_closed_without_leaking_secrets(
    httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
) -> None:
    provider = SidecarWrapProvider(
        "https://wrap.example", "secret-token", 1_000, "acme-kms", 2, 256
    )

    httpx_mock.add_response(url="https://wrap.example/wrap", status_code=500)
    with pytest.raises(WrapSidecarError) as http_error:
        await provider.wrap(b"d" * 32)
    assert http_error.value.status == 502
    assert http_error.value.code == "quarantine_wrap_sidecar_http_error"

    httpx_mock.add_response(url="https://wrap.example/wrap", json={"wrong": True})
    with pytest.raises(WrapSidecarError, match="invalid response"):
        await provider.wrap(b"d" * 32)

    oversized = base64.b64encode(b"z" * 257).decode("ascii")
    httpx_mock.add_response(url="https://wrap.example/wrap", json={"wrapped_key_b64": oversized})
    with pytest.raises(WrapSidecarError, match="invalid response"):
        await provider.wrap(b"d" * 32)

    httpx_mock.add_exception(httpx.ConnectError("down"), url="https://wrap.example/wrap")
    with pytest.raises(WrapSidecarError, match="unavailable"):
        await provider.wrap(b"d" * 32)

    httpx_mock.add_exception(httpx.ConnectTimeout("slow"), url="https://wrap.example/wrap")
    with pytest.raises(WrapSidecarError) as timeout_error:
        await provider.wrap(b"d" * 32)
    assert timeout_error.value.status == 504

    await provider.close()
    serialized = str(http_error.value.body()) + caplog.text
    assert "secret-token" not in serialized
    assert base64.b64encode(b"d" * 32).decode("ascii") not in serialized


def test_sidecar_url_policy_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="must use https"):
        SidecarWrapProvider("http://wrap.internal", None, 1_000, "kms", 1, 256)
    with pytest.raises(RuntimeError, match="must use https"):
        SidecarWrapProvider("wrap.example", None, 1_000, "kms", 1, 256)
    with pytest.raises(RuntimeError, match="must use https"):
        SidecarWrapProvider("https://", None, 1_000, "kms", 1, 256)
    provider = SidecarWrapProvider("http://127.0.0.1:9000", None, 1_000, "kms", 1, 256)
    assert provider.key_wrap == "WRAP-SIDECAR"


def test_sidecar_provider_metadata_is_validated_at_creation() -> None:
    for name in ("", "bad name", "bad/name", "x" * 65):
        with pytest.raises(RuntimeError, match="QUARANTINE_WRAP_SIDECAR_NAME"):
            SidecarWrapProvider("https://wrap.example", None, 1_000, name, 1, 256)
    for version in (0, -1, True):
        with pytest.raises(RuntimeError, match="QUARANTINE_WRAP_SIDECAR_VERSION"):
            SidecarWrapProvider("https://wrap.example", None, 1_000, "kms", version, 256)  # type: ignore[arg-type]
    for timeout_ms in (0, -5, 60_001):
        with pytest.raises(RuntimeError, match="QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS"):
            SidecarWrapProvider("https://wrap.example", None, timeout_ms, "kms", 1, 256)
    provider = SidecarWrapProvider("https://wrap.example", None, 60_000, "kms", 1, 256)
    assert provider.envelope_provider() == WrapProviderInfo("kms", 1)


async def test_sidecar_wrap_aborts_oversized_response_stream(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url="https://wrap.example/wrap", content=b"x" * (8 * 1024 * 1024))
    provider = SidecarWrapProvider("https://wrap.example", None, 5_000, "kms", 1, 256)
    try:
        with pytest.raises(WrapSidecarError, match="invalid response"):
            await provider.wrap(b"d" * 32)
    finally:
        await provider.close()


def test_wrap_provider_settings_fail_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUARANTINE_WRAP_PROVIDER", "https-sidecar")
    monkeypatch.delenv("QUARANTINE_WRAP_SIDECAR_URL", raising=False)
    with pytest.raises(RuntimeError, match="QUARANTINE_WRAP_SIDECAR_URL is required"):
        config.load_settings()

    monkeypatch.setenv("QUARANTINE_WRAP_SIDECAR_URL", "http://wrap.internal")
    with pytest.raises(RuntimeError, match="must use https"):
        config.load_settings()

    monkeypatch.setenv("QUARANTINE_WRAP_SIDECAR_URL", "https://wrap.example")
    settings = config.load_settings()
    assert settings.quarantine_wrap_provider == "https-sidecar"
    assert settings.quarantine_wrap_sidecar_timeout_ms == 5_000

    monkeypatch.setenv("QUARANTINE_WRAP_SIDECAR_NAME", "bad name")
    with pytest.raises(RuntimeError, match="QUARANTINE_WRAP_SIDECAR_NAME"):
        config.load_settings()
    monkeypatch.delenv("QUARANTINE_WRAP_SIDECAR_NAME")

    monkeypatch.setenv("QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS", "60001")
    with pytest.raises(RuntimeError, match="QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS"):
        config.load_settings()
    monkeypatch.delenv("QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS")

    monkeypatch.setenv("QUARANTINE_WRAP_PROVIDER", "rsa-oaep")
    with pytest.raises(RuntimeError, match="requires QUARANTINE_WRAP_PROVIDER=https-sidecar"):
        config.load_settings()
    monkeypatch.delenv("QUARANTINE_WRAP_SIDECAR_URL")
    assert config.load_settings().quarantine_wrap_provider == "rsa-oaep"


def test_sidecar_settings_require_sidecar_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QUARANTINE_WRAP_PROVIDER", raising=False)
    for name, value in (
        ("QUARANTINE_WRAP_SIDECAR_URL", "https://wrap.example"),
        ("QUARANTINE_WRAP_SIDECAR_TOKEN", "t" * 32),
        ("QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS", "1000"),
        ("QUARANTINE_WRAP_SIDECAR_NAME", "acme-kms"),
        ("QUARANTINE_WRAP_SIDECAR_VERSION", "2"),
        ("QUARANTINE_WRAP_SIDECAR_WRAPPED_KEY_BYTES", "1024"),
    ):
        monkeypatch.setenv(name, value)
        with pytest.raises(RuntimeError, match=f"{name} requires"):
            config.load_settings()
        monkeypatch.delenv(name)
    assert config.load_settings().quarantine_wrap_provider == "rsa-oaep"


def test_unwrap_injection_environment_fails_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(config.os.environ):
        if name.startswith("QUARANTINE"):
            monkeypatch.delenv(name, raising=False)
    config.assert_no_private_key_environment()
    for name in (
        "QUARANTINE_PRIVATE_KEY",
        "QUARANTINE_PRIVATE_KEY_FILE",
        "QUARANTINE_UNWRAP_URL",
        "QUARANTINE_WRAP_SIDECAR_UNWRAP_ENDPOINT",
    ):
        monkeypatch.setenv(name, "injected")
        with pytest.raises(RuntimeError, match=f"{name} must not be available"):
            config.assert_no_private_key_environment()
        monkeypatch.delenv(name)
    monkeypatch.setenv("QUARANTINE_WRAP_SIDECAR_URL", "https://wrap.example")
    config.assert_no_private_key_environment()


async def test_store_put_with_sidecar_provider_stores_provider_envelope(
    httpx_mock: HTTPXMock,
) -> None:
    public_pem, _ = _keypair()
    repository = SimpleNamespace(
        get=AsyncMock(return_value=None),
        find_memory_state=AsyncMock(return_value=None),
        store=AsyncMock(),
    )
    limiter = SimpleNamespace(
        consume_many=AsyncMock(),
        consume_many_distinct=AsyncMock(),
        with_identity_lock=None,
    )

    async def run_locked(identity: str, operation: object) -> object:
        return await operation(limiter)  # type: ignore[operator]

    limiter.with_identity_lock = run_locked
    httpx_mock.add_response(
        url="https://wrap.example/wrap",
        json={"wrapped_key_b64": base64.b64encode(b"z" * 128).decode("ascii")},
    )
    provider = SidecarWrapProvider("https://wrap.example", None, 1_000, "acme-kms", 2, 256)
    store = QuarantineStore(public_pem, repository, QuarantineLimits(), limiter, provider)
    try:
        result = await store.put(
            {
                "timestamp": "2026-08-08T00:00:00.000Z",
                "kind": "retain_request",
                "reason": "suspicious_content",
                "writerId": "main",
                "payload": {"items": [{"content": "x"}]},
            }
        )
    finally:
        await provider.close()

    assert result["quarantine_id"].startswith("q_")
    stored = repository.store.call_args.args[0]
    encryption = stored["encrypted"]["encryption"]
    assert encryption["key_wrap"] == "WRAP-SIDECAR"
    assert encryption["provider"] == {"name": "acme-kms", "version": 2}
    parse_envelope(stored["encrypted"])


def test_store_size_charging_includes_provider_metadata() -> None:
    public_pem, _ = _keypair()
    quarantine_id = "q_20260808_0123456789abcdef"
    input_ = {
        "timestamp": "2026-08-08T00:00:00.000Z",
        "kind": "retain_request",
        "reason": "suspicious_content",
        "writerId": "main",
        "payload": {"items": [{"content": "x"}]},
    }
    decrypted = {
        "quarantine_id": quarantine_id,
        "created_at": "2026-08-08T00:00:00.000Z",
        "reason": "suspicious_content",
        "writer_id": "main",
        "payload": {"items": [{"content": "x"}]},
    }
    limits = QuarantineLimits(max_item_bytes=estimate_envelope_size(decrypted, 256))
    repository = SimpleNamespace()
    limiter = SimpleNamespace()

    rsa_store = QuarantineStore(public_pem, repository, limits, limiter)
    rsa_store._assert_item_size(input_, quarantine_id)

    provider_store = QuarantineStore(
        public_pem, repository, limits, limiter, StaticWrapProvider(wrapped=b"w" * 256)
    )
    with pytest.raises(HttpError) as exc:
        provider_store._assert_item_size(input_, quarantine_id)
    assert exc.value.status == 413
    assert exc.value.code == "quarantine_item_too_large"
