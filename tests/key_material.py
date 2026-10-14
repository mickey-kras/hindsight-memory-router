"""Process-local reusable PEM strings; encryption still uses fresh keys and IVs."""

from __future__ import annotations

from functools import cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@cache
def rsa_keypair(key_size: int = 2048, *, identity: str = "primary") -> tuple[str, str]:
    """Keep size and identity separate so wrong-key tests can request another key."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return public_pem.decode(), private_pem.decode()
