from __future__ import annotations

import argparse
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def bootstrap_keys(public_key_path: str, private_key_path: str) -> str:
    public_path = Path(public_key_path)
    private_path = Path(private_key_path)
    public_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private_path.parent, 0o700)

    public_value = public_path.read_bytes() if public_path.exists() else None
    private_value = private_path.read_bytes() if private_path.exists() else None
    if private_value is not None:
        os.chmod(private_path, 0o600)
        private_key = serialization.load_pem_private_key(private_value, password=None)
        derived_public = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if public_value is None:
            with public_path.open("xb") as handle:
                handle.write(derived_public)
            os.chmod(public_path, 0o644)
            return "repaired-public-key"
        if _normalize(public_value) != _normalize(derived_public):
            raise RuntimeError("existing quarantine public/private keys do not match")
        return "existing"

    if public_value is not None:
        raise RuntimeError(
            "quarantine public key exists without its private key; refusing to replace review key material"
        )

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with private_path.open("xb") as handle:
        handle.write(private_bytes)
    os.chmod(private_path, 0o600)
    with public_path.open("xb") as handle:
        handle.write(public_bytes)
    os.chmod(public_path, 0o644)
    return "created"


def _normalize(value: bytes) -> bytes:
    return value.replace(b"\r\n", b"\n").strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--private-key", required=True)
    args = parser.parse_args()
    status = bootstrap_keys(args.public_key, args.private_key)
    print(f"quarantine key bootstrap: {status}")


if __name__ == "__main__":
    main()
