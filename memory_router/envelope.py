from __future__ import annotations

import base64
import hmac
import json
import os
import re
from typing import Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .canonical import canonical_json, sha256_hex

AAD_FORMAT = "metadata-v1"
WRAPPED_KEY_FIELD = "wrapped_key_b64"
_REASONS = {"unknown_writer","suspicious_content","suspicious_query","recalled_suspicious_memory","denied_endpoint","auth_failed"}
_QID = re.compile(r"^q_[0-9A-Za-z]+_[0-9a-f]{16}$")


def parse_decrypted(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("decrypted quarantine object must be an object")
    for key in ("quarantine_id", "created_at", "reason"):
        if not isinstance(value.get(key), str) or not value[key]:
            raise ValueError(f"{key} must be a non-empty string")
    if value["reason"] not in _REASONS:
        raise ValueError("invalid quarantine reason")
    if "payload" not in value:
        raise ValueError("decrypted quarantine payload is missing")
    for key in ("writer_id", "source"):
        if key in value and (not isinstance(value[key], str) or not value[key]):
            raise ValueError(f"{key} must be a non-empty string")
    canonical_json(value["payload"])
    return dict(value)


def canonical_decrypted(value: dict[str, Any]) -> str:
    value = parse_decrypted(value)
    result: dict[str, Any] = {
        "quarantine_id": value["quarantine_id"],
        "created_at": value["created_at"],
        "reason": value["reason"],
    }
    if "writer_id" in value:
        result["writer_id"] = value["writer_id"]
    if "source" in value:
        result["source"] = value["source"]
    result["payload"] = value["payload"]
    return canonical_json(result)


def decode_public_key(value: str) -> rsa.RSAPublicKey:
    trimmed = value.strip()
    if not trimmed:
        raise ValueError("QUARANTINE_PUBLIC_KEY is required")
    try:
        pem = trimmed.replace("\\n", "\n").encode() if "BEGIN PUBLIC KEY" in trimmed else base64.b64decode(trimmed, validate=True)
        key = serialization.load_pem_public_key(pem)
    except Exception as exc:
        raise ValueError("QUARANTINE_PUBLIC_KEY must be PEM or base64-encoded PEM") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("QUARANTINE_PUBLIC_KEY must be an RSA public key")
    return key


def decode_private_key(value: str) -> rsa.RSAPrivateKey:
    trimmed = value.strip()
    if not trimmed:
        raise ValueError("private key is required")
    try:
        pem = trimmed.replace("\\n", "\n").encode() if "BEGIN " in trimmed else base64.b64decode(trimmed, validate=True)
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception as exc:
        raise ValueError("private key must be PEM or base64-encoded PEM") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("private key must be an RSA private key")
    return key


def _aad(envelope: dict[str, Any]) -> bytes:
    encryption = envelope["encryption"]
    result: dict[str, Any] = {
        "version": envelope["version"],
        "quarantine_id": envelope["quarantine_id"],
        "created_at": envelope["created_at"],
        "reason": envelope["reason"],
    }
    if "writer_id" in envelope:
        result["writer_id"] = envelope["writer_id"]
    if "source" in envelope:
        result["source"] = envelope["source"]
    result["sha256"] = envelope["sha256"]
    result["encryption"] = {
        "algorithm": encryption["algorithm"],
        "key_wrap": encryption["key_wrap"],
        "aad": AAD_FORMAT,
        WRAPPED_KEY_FIELD: encryption[WRAPPED_KEY_FIELD],
        "iv_b64": encryption["iv_b64"],
    }
    return canonical_json(result).encode("utf-8")


def create_envelope(value: dict[str, Any], public_key_input: str) -> dict[str, Any]:
    parsed = parse_decrypted(value)
    plaintext = canonical_decrypted(parsed).encode("utf-8")
    key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    wrapped = decode_public_key(public_key_input).encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    envelope: dict[str, Any] = {
        "version": 1,
        "quarantine_id": parsed["quarantine_id"],
        "created_at": parsed["created_at"],
        "reason": parsed["reason"],
    }
    if "writer_id" in parsed:
        envelope["writer_id"] = parsed["writer_id"]
    if "source" in parsed:
        envelope["source"] = parsed["source"]
    envelope["sha256"] = sha256_hex(plaintext.decode("utf-8"))
    envelope["encryption"] = {
        "algorithm": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
        "aad": AAD_FORMAT,
        WRAPPED_KEY_FIELD: base64.b64encode(wrapped).decode("ascii"),
        "iv_b64": base64.b64encode(iv).decode("ascii"),
    }
    ciphertext_tag = AESGCM(key).encrypt(iv, plaintext, _aad(envelope))
    envelope["encryption"]["tag_b64"] = base64.b64encode(ciphertext_tag[-16:]).decode("ascii")
    envelope["ciphertext_b64"] = base64.b64encode(ciphertext_tag[:-16]).decode("ascii")
    return envelope


def parse_envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("encryption"), dict):
        raise ValueError("encrypted quarantine envelope must be an object")
    envelope = dict(value)
    encryption = dict(envelope["encryption"])
    if envelope.get("version") != 1:
        raise ValueError("unsupported quarantine envelope version")
    if encryption.get("algorithm") != "AES-256-GCM":
        raise ValueError("unsupported quarantine encryption algorithm")
    if encryption.get("key_wrap") != "RSA-OAEP-SHA256":
        raise ValueError("unsupported quarantine key wrapping algorithm")
    if encryption.get("aad") not in (None, AAD_FORMAT):
        raise ValueError("unsupported quarantine AAD format")
    if not isinstance(envelope.get("quarantine_id"), str) or not _QID.fullmatch(envelope["quarantine_id"]):
        raise ValueError("invalid quarantine_id")
    if envelope.get("reason") not in _REASONS:
        raise ValueError("invalid quarantine reason")
    if not isinstance(envelope.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", envelope["sha256"]):
        raise ValueError("invalid quarantine object digest")
    for field in (WRAPPED_KEY_FIELD, "iv_b64", "tag_b64"):
        if not isinstance(encryption.get(field), str):
            raise ValueError(f"{field} must be valid base64")
        base64.b64decode(encryption[field], validate=True)
    if len(base64.b64decode(encryption["iv_b64"], validate=True)) != 12:
        raise ValueError("invalid AES-GCM initialization vector length")
    if len(base64.b64decode(encryption["tag_b64"], validate=True)) != 16:
        raise ValueError("invalid AES-GCM authentication tag length")
    if not isinstance(envelope.get("ciphertext_b64"), str):
        raise ValueError("ciphertext_b64 must be valid base64")
    base64.b64decode(envelope["ciphertext_b64"], validate=True)
    return envelope


def decrypt_envelope(value: Any, private_key_input: str) -> dict[str, Any]:
    envelope = parse_envelope(value)
    encryption = envelope["encryption"]
    key = decode_private_key(private_key_input).decrypt(
        base64.b64decode(encryption[WRAPPED_KEY_FIELD]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    if len(key) != 32:
        raise ValueError("invalid decrypted quarantine key length")
    combined = base64.b64decode(envelope["ciphertext_b64"]) + base64.b64decode(encryption["tag_b64"])
    aad = _aad(envelope) if encryption.get("aad") == AAD_FORMAT else None
    plaintext = AESGCM(key).decrypt(base64.b64decode(encryption["iv_b64"]), combined, aad).decode("utf-8")
    if not hmac.compare_digest(sha256_hex(plaintext), envelope["sha256"]):
        raise ValueError("quarantine object digest mismatch")
    parsed = parse_decrypted(json.loads(plaintext))
    for field in ("quarantine_id", "created_at", "reason", "writer_id", "source"):
        if parsed.get(field) != envelope.get(field):
            raise ValueError("quarantine envelope metadata mismatch")
    return parsed
