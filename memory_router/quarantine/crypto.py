from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from memory_router.models import REVIEW_REASONS

AES_KEY_BYTES = 32
GCM_IV_BYTES = 12
GCM_TAG_BYTES = 16
AAD_FORMAT = "metadata-v1"
_QID = re.compile(r"^q_[0-9A-Za-z]+_[0-9a-f]{16}$")
_HEX256 = re.compile(r"^[0-9a-f]{64}$")
_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def canonical_json(value: Any) -> bytes:
    return rfc8785.dumps(value)


def sha256_hex(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class DecryptedQuarantineObject:
    quarantine_id: str
    created_at: str
    reason: str
    payload: Any
    writer_id: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "quarantine_id": self.quarantine_id,
            "created_at": self.created_at,
            "reason": self.reason,
            **({"writer_id": self.writer_id} if self.writer_id is not None else {}),
            **({"source": self.source} if self.source is not None else {}),
            "payload": self.payload,
        }


def canonicalize_decrypted(value: Any) -> bytes:
    return canonical_json(parse_decrypted(value).to_dict())


def decode_public_key(value: str):
    raw = _decode_public_pem(value)
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("QUARANTINE_PUBLIC_KEY must be an RSA public key")
    return key


def decode_private_key(value: str):
    raw = value.strip()
    if not raw:
        raise ValueError("private key is required")
    try:
        pem = raw.replace("\\n", "\n").encode() if "BEGIN " in raw else base64.b64decode(raw, validate=True)
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception as exc:
        raise ValueError("private key must be PEM or base64-encoded PEM") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("private key must be an RSA private key")
    return key


def create_envelope(value: DecryptedQuarantineObject | Mapping[str, Any], public_key_input: str) -> dict[str, Any]:
    decrypted = parse_decrypted(value)
    plaintext = canonicalize_decrypted(decrypted.to_dict())
    key = AESGCM.generate_key(bit_length=256)
    iv = __import__("os").urandom(GCM_IV_BYTES)
    wrapped = decode_public_key(public_key_input).encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    metadata: dict[str, Any] = {
        "version": 1,
        "quarantine_id": decrypted.quarantine_id,
        "created_at": decrypted.created_at,
        "reason": decrypted.reason,
        **({"writer_id": decrypted.writer_id} if decrypted.writer_id is not None else {}),
        **({"source": decrypted.source} if decrypted.source is not None else {}),
        "sha256": sha256_hex(plaintext),
        "encryption": {
            "algorithm": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            "aad": AAD_FORMAT,
            "wrapped_key_b64": base64.b64encode(wrapped).decode(),
            "iv_b64": base64.b64encode(iv).decode(),
        },
    }
    sealed = AESGCM(key).encrypt(iv, plaintext, _authenticated_metadata(metadata))
    ciphertext, tag = sealed[:-GCM_TAG_BYTES], sealed[-GCM_TAG_BYTES:]
    return {
        **metadata,
        "encryption": {**metadata["encryption"], "tag_b64": base64.b64encode(tag).decode()},
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
    }


def parse_envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("encrypted quarantine envelope must be an object")
    encryption = value.get("encryption")
    if not isinstance(encryption, dict):
        raise ValueError("encryption metadata must be an object")
    if value.get("version") != 1:
        raise ValueError("unsupported quarantine envelope version")
    if encryption.get("algorithm") != "AES-256-GCM":
        raise ValueError("unsupported quarantine encryption algorithm")
    if encryption.get("key_wrap") != "RSA-OAEP-SHA256":
        raise ValueError("unsupported quarantine key wrapping algorithm")
    if encryption.get("aad") not in {None, AAD_FORMAT}:
        raise ValueError("unsupported quarantine AAD format")
    qid = _require_string(value.get("quarantine_id"), "quarantine_id")
    if not _QID.fullmatch(qid):
        raise ValueError("invalid quarantine_id")
    reason = _require_string(value.get("reason"), "reason")
    if reason not in REVIEW_REASONS:
        raise ValueError("invalid quarantine reason")
    digest = _require_string(value.get("sha256"), "sha256")
    if not _HEX256.fullmatch(digest):
        raise ValueError("invalid quarantine object digest")
    wrapped = _require_string(encryption.get("wrapped_key_b64"), "wrapped key")
    iv = _require_string(encryption.get("iv_b64"), "iv_b64")
    tag = _require_string(encryption.get("tag_b64"), "tag_b64")
    ciphertext = _require_string(value.get("ciphertext_b64"), "ciphertext_b64")
    _decode_b64(wrapped, "wrapped key")
    if len(_decode_b64(iv, "iv_b64")) != GCM_IV_BYTES:
        raise ValueError("invalid AES-GCM initialization vector length")
    if len(_decode_b64(tag, "tag_b64")) != GCM_TAG_BYTES:
        raise ValueError("invalid AES-GCM authentication tag length")
    _decode_b64(ciphertext, "ciphertext_b64", allow_empty=True)
    writer_id = _optional_string(value.get("writer_id"), "writer_id")
    source = _optional_string(value.get("source"), "source")
    return {
        "version": 1,
        "quarantine_id": qid,
        "created_at": _require_string(value.get("created_at"), "created_at"),
        "reason": reason,
        **({"writer_id": writer_id} if writer_id is not None else {}),
        **({"source": source} if source is not None else {}),
        "sha256": digest,
        "encryption": {
            "algorithm": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            **({"aad": AAD_FORMAT} if encryption.get("aad") == AAD_FORMAT else {}),
            "wrapped_key_b64": wrapped,
            "iv_b64": iv,
            "tag_b64": tag,
        },
        "ciphertext_b64": ciphertext,
    }


def decrypt_envelope(value: Any, private_key_input: str) -> DecryptedQuarantineObject:
    envelope = parse_envelope(value)
    enc = envelope["encryption"]
    key = decode_private_key(private_key_input).decrypt(
        _decode_b64(enc["wrapped_key_b64"], "wrapped key"),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    if len(key) != AES_KEY_BYTES:
        raise ValueError("invalid decrypted quarantine key length")
    iv = _decode_b64(enc["iv_b64"], "iv_b64")
    tag = _decode_b64(enc["tag_b64"], "tag_b64")
    ciphertext = _decode_b64(envelope["ciphertext_b64"], "ciphertext_b64", allow_empty=True)
    aad = _authenticated_metadata(envelope) if enc.get("aad") == AAD_FORMAT else None
    plaintext = AESGCM(key).decrypt(iv, ciphertext + tag, aad)
    if sha256_hex(plaintext) != envelope["sha256"]:
        raise ValueError("quarantine object digest mismatch")
    decrypted = parse_decrypted(json.loads(plaintext.decode("utf-8")))
    if (
        decrypted.quarantine_id != envelope["quarantine_id"]
        or decrypted.created_at != envelope["created_at"]
        or decrypted.reason != envelope["reason"]
        or decrypted.writer_id != envelope.get("writer_id")
        or decrypted.source != envelope.get("source")
    ):
        raise ValueError("quarantine envelope metadata mismatch")
    return decrypted


def parse_decrypted(value: Any) -> DecryptedQuarantineObject:
    if isinstance(value, DecryptedQuarantineObject):
        return value
    if not isinstance(value, dict):
        raise ValueError("decrypted quarantine object must be an object")
    reason = _require_string(value.get("reason"), "reason")
    if reason not in REVIEW_REASONS:
        raise ValueError("invalid quarantine reason")
    if "payload" not in value:
        raise ValueError("decrypted quarantine payload is missing")
    try:
        canonical_json(value["payload"])
    except Exception as exc:
        raise ValueError("payload must contain JSON values only") from exc
    return DecryptedQuarantineObject(
        quarantine_id=_require_string(value.get("quarantine_id"), "quarantine_id"),
        created_at=_require_string(value.get("created_at"), "created_at"),
        reason=reason,
        writer_id=_optional_string(value.get("writer_id"), "writer_id"),
        source=_optional_string(value.get("source"), "source"),
        payload=value["payload"],
    )


def _authenticated_metadata(envelope: Mapping[str, Any]) -> bytes:
    enc = envelope["encryption"]
    return canonical_json(
        {
            "version": envelope["version"],
            "quarantine_id": envelope["quarantine_id"],
            "created_at": envelope["created_at"],
            "reason": envelope["reason"],
            **({"writer_id": envelope["writer_id"]} if "writer_id" in envelope else {}),
            **({"source": envelope["source"]} if "source" in envelope else {}),
            "sha256": envelope["sha256"],
            "encryption": {
                "algorithm": enc["algorithm"],
                "key_wrap": enc["key_wrap"],
                "aad": AAD_FORMAT,
                "wrapped_key_b64": enc["wrapped_key_b64"],
                "iv_b64": enc["iv_b64"],
            },
        }
    )



def _decode_public_pem(value: str) -> bytes:
    raw = value.strip()
    if not raw:
        raise ValueError("QUARANTINE_PUBLIC_KEY is required")
    try:
        pem = raw.replace("\\n", "\n").encode() if "BEGIN " in raw else base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError("QUARANTINE_PUBLIC_KEY must be PEM or base64-encoded PEM") from exc
    if b"BEGIN PUBLIC KEY" not in pem and b"BEGIN RSA PUBLIC KEY" not in pem:
        raise ValueError("QUARANTINE_PUBLIC_KEY must be PEM or base64-encoded PEM")
    return pem

def _decode_pem(value: str, marker: str, label: str) -> bytes:
    raw = value.strip()
    if not raw:
        raise ValueError(f"{label} is required")
    try:
        pem = raw.replace("\\n", "\n").encode() if f"BEGIN {marker}" in raw else base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError(f"{label} must be PEM or base64-encoded PEM") from exc
    if f"BEGIN {marker}".encode() not in pem:
        raise ValueError(f"{label} must be PEM or base64-encoded PEM")
    return pem


def _decode_b64(value: str, label: str, *, allow_empty: bool = False) -> bytes:
    if value == "" and allow_empty:
        return b""
    if not _B64.fullmatch(value) or len(value) % 4:
        raise ValueError(f"{label} must be valid base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"{label} must be valid base64") from exc
    if (not decoded and not allow_empty) or base64.b64encode(decoded).decode() != value:
        raise ValueError(f"{label} must be valid base64")
    return decoded


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _optional_string(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _require_string(value, label)
