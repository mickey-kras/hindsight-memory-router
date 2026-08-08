from __future__ import annotations

import base64
import copy
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from memory_router.quarantine.crypto import (
    AAD_FORMAT,
    DecryptedQuarantineObject,
    canonical_json,
    canonicalize_decrypted,
    create_envelope,
    decode_private_key,
    decode_public_key,
    decrypt_envelope,
    parse_decrypted,
    parse_envelope,
    sha256_hex,
)
from tests.helpers import keypair


def sample():
    return DecryptedQuarantineObject(
        quarantine_id="q_20260808T000000000Z_0123456789abcdef",
        created_at="2026-08-08T00:00:00.000Z",
        reason="suspicious_content",
        writer_id="main",
        source="openclaw",
        payload={"action": "retain", "body": {"items": [{"content": "x"}]}},
    )


def test_envelope_roundtrip_and_aad_tamper_detection():
    public, private = keypair()
    value = sample()
    envelope = create_envelope(value, public)
    assert envelope["version"] == 1
    assert envelope["encryption"]["algorithm"] == "AES-256-GCM"
    assert envelope["encryption"]["key_wrap"] == "RSA-OAEP-SHA256"
    assert envelope["encryption"]["aad"] == AAD_FORMAT
    assert decrypt_envelope(envelope, private) == value
    assert decode_public_key(base64.b64encode(public.encode()).decode()).key_size == 2048
    assert decode_private_key(base64.b64encode(private.encode()).decode()).key_size == 2048

    tampered = copy.deepcopy(envelope)
    tampered["source"] = "evil"
    with pytest.raises(Exception):
        decrypt_envelope(tampered, private)


def test_legacy_v1_without_aad_still_decrypts():
    public, private = keypair()
    value = sample()
    plaintext = canonicalize_decrypted(value.to_dict())
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    sealed = AESGCM(aes_key).encrypt(iv, plaintext, None)
    public_key = decode_public_key(public)
    wrapped = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    envelope = {
        "version": 1,
        "quarantine_id": value.quarantine_id,
        "created_at": value.created_at,
        "reason": value.reason,
        "writer_id": value.writer_id,
        "source": value.source,
        "sha256": sha256_hex(plaintext),
        "encryption": {
            "algorithm": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            "wrapped_key_b64": base64.b64encode(wrapped).decode(),
            "iv_b64": base64.b64encode(iv).decode(),
            "tag_b64": base64.b64encode(sealed[-16:]).decode(),
        },
        "ciphertext_b64": base64.b64encode(sealed[:-16]).decode(),
    }
    assert decrypt_envelope(envelope, private) == value


def test_crypto_validation_rejects_malformed_envelopes_and_payloads():
    public, private = keypair()
    envelope = create_envelope(sample(), public)
    for mutation in [
        None,
        {**envelope, "version": 2},
        {**envelope, "quarantine_id": "bad"},
        {**envelope, "reason": "bad"},
        {**envelope, "sha256": "bad"},
    ]:
        with pytest.raises(ValueError):
            parse_envelope(mutation)
    with pytest.raises(ValueError):
        decode_public_key("")
    with pytest.raises(ValueError):
        decode_private_key("not a key")
    with pytest.raises(ValueError):
        parse_decrypted([])
    with pytest.raises(ValueError):
        parse_decrypted({"quarantine_id": "x", "created_at": "x", "reason": "suspicious_content"})


def test_canonical_hash_is_deterministic():
    left = canonical_json({"b": 1, "a": [True, "x"]})
    right = canonical_json({"a": [True, "x"], "b": 1})
    assert left == right
    assert sha256_hex(left) == sha256_hex(right)


def test_crypto_validation_covers_metadata_and_base64_boundaries():
    public, private = keypair()
    env = create_envelope(sample(), public)
    mutations = []
    for key, value in [("algorithm","bad"),("key_wrap","bad"),("aad","bad")]:
        item = copy.deepcopy(env); item["encryption"][key] = value; mutations.append(item)
    item = copy.deepcopy(env); item["encryption"] = "bad"; mutations.append(item)
    for field in ["wrapped_key_b64","iv_b64","tag_b64"]:
        item = copy.deepcopy(env); item["encryption"][field] = "***"; mutations.append(item)
    item = copy.deepcopy(env); item["encryption"]["iv_b64"] = base64.b64encode(b"short").decode(); mutations.append(item)
    item = copy.deepcopy(env); item["encryption"]["tag_b64"] = base64.b64encode(b"short").decode(); mutations.append(item)
    item = copy.deepcopy(env); item["ciphertext_b64"] = "***"; mutations.append(item)
    item = copy.deepcopy(env); item["writer_id"] = 1; mutations.append(item)
    item = copy.deepcopy(env); item["source"] = 1; mutations.append(item)
    for item in mutations:
        with pytest.raises(ValueError):
            parse_envelope(item)

    with pytest.raises(ValueError, match="RSA public"):
        # A valid PEM of the wrong key type.
        from cryptography.hazmat.primitives.asymmetric import ec
        ec_pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        decode_public_key(ec_pub)
    with pytest.raises(ValueError, match="RSA private"):
        from cryptography.hazmat.primitives.asymmetric import ec
        ec_priv = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        decode_private_key(ec_priv)
    with pytest.raises(ValueError):
        decode_public_key("not-base64")
    with pytest.raises(ValueError):
        parse_decrypted({"quarantine_id":"x","created_at":"x","reason":"bad","payload":{}})
    with pytest.raises(ValueError):
        parse_decrypted({"quarantine_id":"x","created_at":"x","reason":"suspicious_content","payload":{1}})
