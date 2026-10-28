from __future__ import annotations

import base64
import json
import sqlite3
import sys
import threading
from collections.abc import Mapping
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from memory_router.cli.review_agent import ReviewAgent, ReviewAudit
from memory_router.envelope import _aad, create_envelope, create_provider_envelope, decrypt_envelope
from memory_router.key_wrap import WrapProviderInfo
from memory_router.review_unwrap import (
    Pkcs11RsaOaepProvider,
    ReviewProviderId,
    ReviewProviderRegistry,
    load_review_provider,
)

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
ITEM = {
    "quarantine_id": "q_test_0123456789abcdef",
    "created_at": "2026-01-01T00:00:00Z",
    "reason": "suspicious_content",
    "writer_id": "review-test",
    "payload": {"text": "synthetic evidence only"},
}


class WrapFixture:
    key_wrap = "WRAP-SIDECAR"
    wrapped_key_bytes = 256

    def __init__(self, key: rsa.RSAPublicKey) -> None:
        self.key = key

    def envelope_provider(self) -> WrapProviderInfo:
        return WrapProviderInfo("mock-external", 1)

    async def wrap(self, dek: bytes) -> bytes:
        return self.key.encrypt(dek, OAEP)

    async def close(self) -> None:
        pass


class MockExternalUnwrapper:
    identity = ReviewProviderId("WRAP-SIDECAR", "mock-external", 1)

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        self.key = key

    def unwrap(self, wrapped_dek: bytes, envelope: Mapping[str, Any]) -> bytes:
        return self.key.decrypt(wrapped_dek, OAEP)


@pytest.fixture
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
async def provider_envelope(rsa_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    return await create_provider_envelope(ITEM, WrapFixture(rsa_key.public_key()))


def _reseal(envelope: dict[str, Any], key: rsa.RSAPrivateKey) -> None:
    enc = envelope["encryption"]
    dek = key.decrypt(base64.b64decode(enc["wrapped_key_b64"]), OAEP)
    # Reuse the original canonical plaintext to test authenticated-but-inconsistent metadata.
    from memory_router.envelope import canonical_decrypted

    combined = AESGCM(dek).encrypt(
        base64.b64decode(enc["iv_b64"]), canonical_decrypted(ITEM).encode(), _aad(envelope)
    )
    envelope["ciphertext_b64"] = base64.b64encode(combined[:-16]).decode()
    enc["tag_b64"] = base64.b64encode(combined[-16:]).decode()


async def test_external_review_provider_verifies_synthetic_envelope(
    provider_envelope: dict[str, Any], rsa_key: rsa.RSAPrivateKey
) -> None:
    registry = ReviewProviderRegistry([MockExternalUnwrapper(rsa_key)])
    assert registry.decrypt(provider_envelope) == ITEM
    with pytest.raises(ValueError, match="matching review unwrap provider"):
        ReviewProviderRegistry([]).decrypt(provider_envelope)
    with pytest.raises(ValueError, match="matching review unwrap provider"):
        ReviewProviderRegistry([Pkcs11RsaOaepProvider("driver", "token", "key", "123456")]).decrypt(
            provider_envelope
        )
    with pytest.raises(ValueError, match="matching review unwrap provider"):
        ReviewProviderRegistry([MockExternalUnwrapper(rsa_key)]).decrypt(
            {
                **provider_envelope,
                "encryption": {
                    **provider_envelope["encryption"],
                    "provider": {"name": "mock-external", "version": 2},
                },
            }
        )


async def test_external_review_fail_closed(
    provider_envelope: dict[str, Any], rsa_key: rsa.RSAPrivateKey
) -> None:
    registry = ReviewProviderRegistry([MockExternalUnwrapper(rsa_key)])
    with pytest.raises(InvalidTag):
        registry.decrypt({**provider_envelope, "ciphertext_b64": "AA=="})
    changed = json.loads(json.dumps(provider_envelope))
    changed["encryption"]["provider"]["name"] = "other"
    with pytest.raises(ValueError, match="matching review unwrap provider"):
        registry.decrypt(changed)
    changed = json.loads(json.dumps(provider_envelope))
    changed["sha256"] = "0" * 64
    _reseal(changed, rsa_key)
    with pytest.raises(ValueError, match="digest mismatch"):
        registry.decrypt(changed)
    changed = json.loads(json.dumps(provider_envelope))
    changed["reason"] = "unknown_writer"
    _reseal(changed, rsa_key)
    with pytest.raises(ValueError, match="metadata mismatch"):
        registry.decrypt(changed)
    bad_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(ValueError):
        ReviewProviderRegistry([MockExternalUnwrapper(bad_key)]).decrypt(provider_envelope)

    class ShortUnwrapper(MockExternalUnwrapper):
        def unwrap(self, wrapped_dek: bytes, envelope: Mapping[str, Any]) -> bytes:
            return b"a" * 31

    with pytest.raises(ValueError, match="key length"):
        ReviewProviderRegistry([ShortUnwrapper(rsa_key)]).decrypt(provider_envelope)
    with pytest.raises(ValueError, match="duplicate"):
        ReviewProviderRegistry([MockExternalUnwrapper(rsa_key), MockExternalUnwrapper(rsa_key)])

    class DifferentVersion(MockExternalUnwrapper):
        identity = ReviewProviderId("WRAP-SIDECAR", "mock-external", 2)

    changed = json.loads(json.dumps(provider_envelope))
    changed["encryption"]["provider"]["version"] = 2
    with pytest.raises(InvalidTag):
        ReviewProviderRegistry([DifferentVersion(rsa_key)]).decrypt(changed)


def test_external_entrypoint_is_selected_explicitly(
    monkeypatch: pytest.MonkeyPatch, rsa_key: rsa.RSAPrivateKey
) -> None:
    import memory_router.review_unwrap as module

    loaded = Mock(return_value=Mock(return_value=MockExternalUnwrapper(rsa_key)))
    selected = SimpleNamespace(name="my-provider", load=loaded)
    monkeypatch.setattr(module, "entry_points", lambda group: [selected])
    assert load_review_provider("my-provider").identity == MockExternalUnwrapper.identity
    loaded.assert_called_once_with()
    with pytest.raises(ValueError, match="missing or ambiguous"):
        load_review_provider("other-provider")


def test_native_rsa_compatibility_and_pkcs11_boundary(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    public_pem = (
        rsa_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    private_pem = rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    envelope = create_envelope(ITEM, public_pem)
    assert decrypt_envelope(envelope, private_pem) == ITEM
    seen: dict[str, Any] = {}

    class FakeSession:
        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def get_key(self, **kwargs: Any) -> FakeSession:
            seen["lookup"] = kwargs
            return self

        def decrypt(self, wrapped: bytes, **kwargs: Any) -> bytes:
            seen["mechanism"] = kwargs
            return rsa_key.decrypt(wrapped, OAEP)

    session = FakeSession()

    class FakeToken:
        def open(self, user_pin: str) -> FakeSession:
            seen["pin"] = user_pin
            return session

    mock_module = SimpleNamespace(
        lib=lambda path: (
            seen.setdefault("module", path)
            and SimpleNamespace(
                get_token=lambda token_label: seen.setdefault("token", token_label) and FakeToken()
            )
        ),
        ObjectClass=SimpleNamespace(PRIVATE_KEY=1),
        KeyType=SimpleNamespace(RSA=2),
        Mechanism=SimpleNamespace(RSA_PKCS_OAEP=3, SHA256=4),
    )
    monkeypatch.setitem(sys.modules, "pkcs11", mock_module)
    monkeypatch.setitem(
        sys.modules, "pkcs11.mechanisms", SimpleNamespace(MGF=SimpleNamespace(SHA256=5))
    )
    hardware = Pkcs11RsaOaepProvider("module.so", "review-token", "review-key", "pin")
    assert ReviewProviderRegistry([hardware]).decrypt(envelope) == ITEM
    assert seen == {
        "module": "module.so",
        "token": "review-token",
        "pin": "pin",
        "lookup": {"object_class": 1, "key_type": 2, "label": "review-key"},
        "mechanism": {"mechanism": 3, "mechanism_param": (4, 5, None)},
    }


def test_review_agent_authentication_and_bounded_audit(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey
) -> None:
    public_pem = (
        rsa_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    envelope = create_envelope(ITEM, public_pem)

    class NativeMock:
        identity = ReviewProviderId("RSA-OAEP-SHA256")

        def unwrap(self, wrapped_dek: bytes, _: Mapping[str, Any]) -> bytes:
            return rsa_key.decrypt(wrapped_dek, OAEP)

    audit = ReviewAudit(tmp_path / "review.sqlite3")
    agent = ReviewAgent(
        0,
        "http://localhost:5173",
        "t" * 32,
        "misha",
        ReviewProviderRegistry([NativeMock()]),
        audit,
    )
    thread = threading.Thread(target=agent.serve_forever)
    thread.start()
    try:

        def request(origin: str, token: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
            conn = HTTPConnection("127.0.0.1", agent.server_port)
            conn.request(
                "POST",
                "/decrypt",
                json.dumps(body),
                headers={
                    "Origin": origin,
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            response = conn.getresponse()
            result = response.status, json.loads(response.read())
            conn.close()
            return result

        assert request("http://evil.example", "t" * 32, {"envelope": envelope})[0] == 403
        assert request("http://localhost:5173", "wrong", {"envelope": envelope})[0] == 403
        status, payload = request("http://localhost:5173", "t" * 32, {"envelope": envelope})
        assert status == 200
        assert payload == {"decrypted": ITEM}
        assert request("http://localhost:5173", "t" * 32, {"envelope": {}})[0] == 400
        with sqlite3.connect(tmp_path / "review.sqlite3") as db:
            rows = db.execute(
                "SELECT reviewer, quarantine_id, outcome FROM review_audit ORDER BY id"
            ).fetchall()
        assert rows == [
            ("misha", None, "unauthorized"),
            ("misha", None, "unauthorized"),
            ("misha", ITEM["quarantine_id"], "verified"),
            ("misha", None, "failed"),
        ]
        for _ in range(1001):
            audit.record("misha", None, "unauthorized")
        with sqlite3.connect(tmp_path / "review.sqlite3") as db:
            assert db.execute("SELECT COUNT(*) FROM review_audit").fetchone() == (1000,)
    finally:
        agent.shutdown()
        agent.server_close()
        thread.join()
