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


@pytest.mark.parametrize("always_authenticate", [False, True])
def test_native_rsa_compatibility_and_pkcs11_boundary(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch, always_authenticate: bool
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

        def __getitem__(self, attribute: int) -> bool:
            assert attribute == 6
            return always_authenticate

        def decrypt(self, wrapped: bytes, **kwargs: Any) -> bytes:
            if always_authenticate:
                # Session login alone does not authorize an ALWAYS_AUTHENTICATE key.
                assert kwargs.get("pin") == "pin"
            else:
                assert "pin" not in kwargs
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
        Attribute=SimpleNamespace(ALWAYS_AUTHENTICATE=6),
    )
    monkeypatch.setitem(sys.modules, "pkcs11", mock_module)
    monkeypatch.setitem(
        sys.modules, "pkcs11.mechanisms", SimpleNamespace(MGF=SimpleNamespace(SHA256=5))
    )
    hardware = Pkcs11RsaOaepProvider("module.so", "review-token", "review-key", "pin")
    assert ReviewProviderRegistry([hardware]).decrypt(envelope) == ITEM
    assert ReviewProviderRegistry([hardware]).decrypt(envelope) == ITEM
    assert seen == {
        "module": "module.so",
        "token": "review-token",
        "pin": "pin",
        "lookup": {"object_class": 1, "key_type": 2, "label": "review-key"},
        "mechanism": {
            "mechanism": 3,
            "mechanism_param": (4, 5, None),
            **({"pin": "pin"} if always_authenticate else {}),
        },
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
        fail = False

        def unwrap(self, wrapped_dek: bytes, _: Mapping[str, Any]) -> bytes:
            if self.fail:
                raise RuntimeError("private provider failure details")
            return rsa_key.decrypt(wrapped_dek, OAEP)

    audit = ReviewAudit(tmp_path / "review.sqlite3")
    provider = NativeMock()
    agent = ReviewAgent(
        0,
        "http://localhost:5173",
        "t" * 32,
        "misha",
        ReviewProviderRegistry([provider]),
        audit,
    )
    thread = threading.Thread(target=agent.serve_forever)
    thread.start()
    try:
        assert agent.socket.getsockname() == ("127.0.0.1", agent.server_port)

        def request(
            origin: str, token: str, body: dict[str, Any] | bytes
        ) -> tuple[int, dict[str, Any]]:
            conn = HTTPConnection("127.0.0.1", agent.server_port)
            conn.request(
                "POST",
                "/decrypt",
                body if isinstance(body, bytes) else json.dumps(body),
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
        assert request("http://localhost:5173", "wrong", {"malformed": True})[0] == 403
        assert request("http://localhost:5173", "é" * 32, {"envelope": envelope}) == (
            403,
            {"error": "unauthorized"},
        )
        status, payload = request("http://localhost:5173", "t" * 32, {"envelope": envelope})
        assert status == 200
        assert payload == {"decrypted": ITEM}
        assert request("http://localhost:5173", "t" * 32, {"envelope": {}})[0] == 400
        for malformed_body in (b"{", b"\xff"):
            assert request("http://localhost:5173", "t" * 32, malformed_body) == (
                400,
                {"error": "invalid_envelope"},
            )
        provider.fail = True
        assert request("http://localhost:5173", "t" * 32, {"envelope": envelope}) == (
            422,
            {"error": "review_decrypt_failed"},
        )
        with sqlite3.connect(tmp_path / "review.sqlite3") as db:
            rows = db.execute(
                "SELECT reviewer, quarantine_id, outcome FROM review_audit ORDER BY id"
            ).fetchall()
        assert rows == [
            ("misha", None, "unauthorized"),
            ("misha", None, "unauthorized"),
            ("misha", None, "unauthorized"),
            ("misha", None, "unauthorized"),
            ("misha", ITEM["quarantine_id"], "verified"),
            ("misha", None, "failed"),
            ("misha", None, "failed"),
            ("misha", None, "failed"),
            ("misha", ITEM["quarantine_id"], "failed"),
        ]
        for _ in range(1001):
            audit.record("misha", None, "unauthorized")
        with sqlite3.connect(tmp_path / "review.sqlite3") as db:
            assert db.execute("SELECT COUNT(*) FROM review_audit").fetchone() == (105,)
            assert db.execute(
                "SELECT quarantine_id FROM review_audit WHERE outcome = 'verified'"
            ).fetchall() == [(ITEM["quarantine_id"],)]
            assert db.execute(
                "SELECT COUNT(*) FROM review_audit WHERE outcome = 'failed'"
            ).fetchone() == (4,)
        for _ in range(1001):
            audit.record("misha", None, "failed")
        with sqlite3.connect(tmp_path / "review.sqlite3") as db:
            assert db.execute("SELECT COUNT(*) FROM review_audit").fetchone() == (1000,)
    finally:
        agent.shutdown()
        agent.server_close()
        thread.join()


@pytest.mark.parametrize("extra_bytes, expected_status", [(0, 200), (1, 200), (2, 400)])
@pytest.mark.parametrize("plaintext_bytes", [0, 2 * 1024 * 1024])
async def test_review_agent_request_byte_boundary(
    tmp_path: Path,
    provider_envelope: dict[str, Any],
    rsa_key: rsa.RSAPrivateKey,
    extra_bytes: int,
    expected_status: int,
    plaintext_bytes: int,
) -> None:
    expected_item = ITEM
    if plaintext_bytes:
        expected_item = {**ITEM, "payload": {"text": "x" * plaintext_bytes}}
        provider_envelope = await create_provider_envelope(
            expected_item, WrapFixture(rsa_key.public_key())
        )
    body = json.dumps({"envelope": provider_envelope}).encode()
    agent = ReviewAgent(
        0,
        "http://localhost:5173",
        "t" * 32,
        "reviewer",
        ReviewProviderRegistry([MockExternalUnwrapper(rsa_key)]),
        ReviewAudit(tmp_path / "audit.sqlite3"),
        max_request_bytes=len(body) + 1,
    )
    thread = threading.Thread(target=agent.serve_forever)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", agent.server_port, timeout=5)
        headers = {
            "Origin": agent.origin,
            "Authorization": "Bearer " + "t" * 32,
            "Content-Type": "application/json",
        }
        if expected_status == 400:
            # Prove rejection before body reads without racing the server's connection close.
            conn.putrequest("POST", "/decrypt")
            for name, value in headers.items():
                conn.putheader(name, value)
            conn.putheader("Content-Length", str(len(body) + extra_bytes))
            conn.endheaders()
        else:
            conn.request("POST", "/decrypt", body + b" " * extra_bytes, headers=headers)
        response = conn.getresponse()
        assert response.status == expected_status
        result = json.loads(response.read())
        assert result == (
            {"decrypted": expected_item}
            if expected_status == 200
            else {"error": "invalid_envelope"}
        )
        conn.close()
    finally:
        agent.shutdown()
        agent.server_close()
        thread.join()


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "invalid"])
def test_review_agent_cli_rejects_invalid_request_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    value: str,
) -> None:
    from memory_router.cli.review_agent import main

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "memory-router-review-agent",
            "--origin",
            "http://localhost:5173",
            "--reviewer",
            "reviewer",
            "--credential-file",
            str(tmp_path / "credential"),
            "--audit-db",
            str(tmp_path / "audit"),
            "--max-request-bytes",
            value,
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


def test_review_agent_cli_fixed_port_and_request_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    import memory_router.cli.review_agent as module

    credential = tmp_path / "credential"
    credential.write_text("t" * 32)
    credential.chmod(0o600)
    server = Mock(server_port=8765)
    constructor = Mock(return_value=server)
    monkeypatch.setattr(module, "ReviewAgent", constructor)
    monkeypatch.setattr(module, "load_review_provider", lambda _: MockExternalUnwrapper(rsa_key))
    argv = [
        "memory-router-review-agent",
        "--origin",
        "http://localhost:5173",
        "--reviewer",
        "reviewer",
        "--credential-file",
        str(credential),
        "--audit-db",
        str(tmp_path / "audit"),
        "--external-provider",
        "fixture",
    ]
    for limit in (1, 128 * 1024 * 1024, None):
        monkeypatch.setattr(
            sys, "argv", argv + ([] if limit is None else ["--max-request-bytes", str(limit)])
        )
        module.main()
        assert constructor.call_args.args[0] == 8765
        assert constructor.call_args.kwargs["max_request_bytes"] == (
            module.MAX_REQUEST_BYTES if limit is None else limit
        )
    monkeypatch.setattr(sys, "argv", [*argv, "--port", "8766"])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2


@pytest.mark.parametrize("credential", ["a" * 31, "é" * 32])
def test_review_agent_rejects_invalid_configured_credential(
    tmp_path: Path,
    credential: str,
) -> None:
    from memory_router.cli.review_agent import _read_credential

    path = tmp_path / "credential"
    path.write_text(credential)
    path.chmod(0o600)
    with pytest.raises(ValueError, match="32 ASCII characters"):
        _read_credential(path)
    with pytest.raises(ValueError, match="32 ASCII characters"):
        ReviewAgent(
            0,
            "http://localhost:5173",
            credential,
            "reviewer",
            ReviewProviderRegistry([]),
            ReviewAudit(tmp_path / "audit.sqlite3"),
        )
