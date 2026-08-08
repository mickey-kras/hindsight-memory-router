from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from memory_router.config import QuarantineLimits
from memory_router.quarantine.db import SqliteDatabase
from memory_router.quarantine.repository import QuarantineRepository
from memory_router.quarantine.store import EncryptedDatabaseQuarantineStore
from memory_router.rate_limits import InMemorySlidingWindowRateLimiter


def keypair() -> tuple[str, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return public_pem, private_pem


async def repository(tmp_path: Path) -> QuarantineRepository:
    repo = QuarantineRepository(SqliteDatabase(str(tmp_path / "q.db")))
    await repo.initialize()
    return repo


async def store(
    tmp_path: Path,
    *,
    limits: QuarantineLimits | None = None,
) -> tuple[EncryptedDatabaseQuarantineStore, QuarantineRepository, str]:
    repo = await repository(tmp_path)
    limiter = InMemorySlidingWindowRateLimiter()
    await limiter.initialize()
    public, private = keypair()
    return (
        EncryptedDatabaseQuarantineStore(public, repo, limits or QuarantineLimits(), limiter),
        repo,
        private,
    )


class FakeHindsight:
    def __init__(self) -> None:
        self.retains: list[tuple[str, Any]] = []
        self.recalls: dict[str, Any] = {}
        self.invalidations: list[tuple[str, str, str]] = []

    async def retain(self, bank: str, body: Any) -> Any:
        self.retains.append((bank, body))
        return {"accepted": True}

    async def recall(self, bank: str, body: Any) -> Any:
        from memory_router.models import RecallResponse

        value = self.recalls.get(bank, {"results": []})
        if isinstance(value, BaseException):
            raise value
        return RecallResponse.model_validate(value)

    async def invalidate_memory(self, bank: str, memory_id: str, reason: str) -> None:
        self.invalidations.append((bank, memory_id, reason))

    async def close(self) -> None:
        return None
