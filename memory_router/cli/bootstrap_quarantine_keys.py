from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def bootstrap_quarantine_keys(
    public_key_path: str,
    private_key_path: str,
    modulus_length: int = 4096,
) -> str:
    public_path = Path(public_key_path)
    private_path = Path(private_key_path)
    public_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private_path.parent, 0o700)

    public = public_path.read_bytes() if public_path.exists() else None
    private = private_path.read_bytes() if private_path.exists() else None

    if private is not None:
        os.chmod(private_path, 0o600)
        private_key = serialization.load_pem_private_key(private, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("existing quarantine private key is not RSA")
        derived = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if public is None:
            _exclusive_write(public_path, derived, 0o644)
            return "repaired-public-key"
        if _normalize_pem(public) != _normalize_pem(derived):
            raise ValueError("existing quarantine public/private keys do not match")
        return "existing"

    if public is not None:
        raise ValueError(
            "quarantine public key exists without its private key; refusing to replace review key material"
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=modulus_length
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _exclusive_write(private_path, private_pem, 0o600)
    os.chmod(private_path, 0o600)
    _exclusive_write(public_path, public_pem, 0o644)
    return "created"


def _exclusive_write(path: Path, content: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _normalize_pem(value: bytes) -> bytes:
    return value.strip().replace(b"\r\n", b"\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--public-key")
    parser.add_argument("--private-key")
    try:
        args = parser.parse_args(argv)
        if not args.public_key or not args.private_key:
            raise ValueError(
                "usage: bootstrap-quarantine-keys --public-key <path> --private-key <path>"
            )
        status = bootstrap_quarantine_keys(args.public_key, args.private_key)
        print(f"quarantine key bootstrap: {status}")
        return 0
    except (Exception, SystemExit) as exc:
        message = str(exc) if not isinstance(exc, SystemExit) else "invalid arguments"
        print(f"quarantine key bootstrap failed: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
