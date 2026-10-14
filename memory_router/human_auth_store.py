from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field

from pydantic import TypeAdapter

from .db import Database, Tx
from .errors import HttpError
from .principals import PrincipalGrant

_GRANTS = TypeAdapter(tuple[PrincipalGrant, ...])
_DUMMY_DIGEST = hashlib.sha256(b"human-session:unknown").hexdigest()
_LOGIN_TTL_MS = 300_000
_SESSION_TTL_MS = 3_600_000
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS human_auth_policy "
    "(id INTEGER PRIMARY KEY, generation TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS human_auth_logins "
    "(transaction_id TEXT PRIMARY KEY, generation TEXT NOT NULL, state TEXT NOT NULL, "
    "challenge TEXT NOT NULL, redirect_uri TEXT NOT NULL, nonce TEXT NOT NULL, "
    "expires_at_ms BIGINT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_human_auth_logins_expiry ON human_auth_logins(expires_at_ms)",
    "CREATE TABLE IF NOT EXISTS human_auth_sessions "
    "(key_id TEXT PRIMARY KEY, generation TEXT NOT NULL, principal_id TEXT NOT NULL, "
    "secret_digest TEXT NOT NULL, grants TEXT NOT NULL, expires_at_ms BIGINT NOT NULL, "
    "revoked INTEGER NOT NULL DEFAULT 0)",
    "CREATE INDEX IF NOT EXISTS idx_human_auth_sessions_expiry "
    "ON human_auth_sessions(expires_at_ms)",
    "CREATE INDEX IF NOT EXISTS idx_human_auth_sessions_principal "
    "ON human_auth_sessions(principal_id, expires_at_ms)",
)


@dataclass(frozen=True, slots=True)
class LoginTransaction:
    redirect_uri: str
    nonce: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class IssuedSession:
    token: str = field(repr=False)
    key_id: str
    expires_at: int


@dataclass(frozen=True, slots=True)
class StoredSession:
    principal_id: str
    key_id: str
    grants: tuple[PrincipalGrant, ...]


async def _now_ms(tx: Tx) -> int:
    if tx.dialect == "postgres":
        row = await tx.fetchone(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms"
        )
        return int((row or {})["now_ms"])
    return time.time_ns() // 1_000_000


def _unavailable() -> HttpError:
    return HttpError(503, "human_auth_policy_inactive", "human login policy is not active")


def _invalid_login() -> HttpError:
    return HttpError(401, "human_login_required", "interactive login is required")


def _capacity() -> HttpError:
    return HttpError(
        429, "human_auth_capacity", "human login capacity exhausted", {"retry-after": "60"}
    )


class HumanAuthStore:
    """Shared, short transactions; callers perform identity-provider I/O after claim_login."""

    def __init__(self, db: Database, generation: str) -> None:
        self.db = db
        self.generation = generation

    async def initialize(self, *, check_generation: bool = True) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            for statement in _SCHEMA:
                await tx.execute(statement)
            await tx.execute(
                "INSERT INTO human_auth_policy(id,generation) VALUES(1,?) "
                "ON CONFLICT(id) DO NOTHING",
                (self.generation,),
            )
            if check_generation:
                await self._require_generation(tx)

    async def _require_generation(self, tx: Tx) -> None:
        row = await tx.fetchone("SELECT generation FROM human_auth_policy WHERE id=1")
        if row is None or row["generation"] != self.generation:
            raise _unavailable()

    async def require_generation(self) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            await self._require_generation(tx)

    async def activate(self) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            await tx.execute(
                "UPDATE human_auth_policy SET generation=? WHERE id=1", (self.generation,)
            )
            await tx.execute("DELETE FROM human_auth_logins")
            # Keep unexpired rows counted against caps even after revocation.
            await tx.execute("UPDATE human_auth_sessions SET revoked=1")
            await self._prune(tx, await _now_ms(tx))

    async def create_login(
        self, *, state: str, challenge: str, redirect_uri: str, nonce: str
    ) -> str:
        transaction_id = secrets.token_urlsafe(32)
        async with self.db.transaction(capacity_lock=True) as tx:
            await self._require_generation(tx)
            now = await _now_ms(tx)
            await self._prune(tx, now)
            await self._require_session_capacity(tx, now)
            row = await tx.fetchone("SELECT COUNT(*) AS count FROM human_auth_logins")
            if row is not None and int(row["count"]) >= 1000:
                raise _capacity()
            await tx.execute(
                "INSERT INTO human_auth_logins "
                "(transaction_id,generation,state,challenge,redirect_uri,nonce,expires_at_ms) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    transaction_id,
                    self.generation,
                    state,
                    challenge,
                    redirect_uri,
                    nonce,
                    now + _LOGIN_TTL_MS,
                ),
            )
        return transaction_id

    async def claim_login(
        self, transaction_id: str, *, state: str, challenge: str
    ) -> LoginTransaction:
        async with self.db.transaction(capacity_lock=True) as tx:
            await self._require_generation(tx)
            now = await _now_ms(tx)
            await self._require_session_capacity(tx, now)
            row = await tx.fetchone(
                "SELECT state,challenge,redirect_uri,nonce FROM human_auth_logins "
                "WHERE transaction_id=? AND generation=? AND expires_at_ms>?",
                (transaction_id, self.generation, now),
            )
            if row is None:
                raise _invalid_login()
            valid_state = hmac.compare_digest(str(row["state"]), state)
            valid_challenge = hmac.compare_digest(str(row["challenge"]), challenge)
            if not (valid_state and valid_challenge):
                raise _invalid_login()
            await tx.execute(
                "DELETE FROM human_auth_logins WHERE transaction_id=?", (transaction_id,)
            )
            result = LoginTransaction(str(row["redirect_uri"]), str(row["nonce"]))
        return result

    async def issue(
        self, *, principal_id: str, grants: tuple[PrincipalGrant, ...]
    ) -> IssuedSession:
        key_id, secret = secrets.token_hex(16), secrets.token_hex(32)
        digest = hashlib.sha256(secret.encode("ascii")).hexdigest()
        async with self.db.transaction(capacity_lock=True) as tx:
            await self._require_generation(tx)
            now = await _now_ms(tx)
            await self._prune(tx, now)
            row = await tx.fetchone(
                "SELECT COUNT(*) AS total, "
                "COALESCE(SUM(CASE WHEN principal_id=? THEN 1 ELSE 0 END),0) AS personal "
                "FROM human_auth_sessions",
                (principal_id,),
            )
            if row is not None and (int(row["total"]) >= 10_000 or int(row["personal"]) >= 20):
                raise _capacity()
            expires_at_ms = now + _SESSION_TTL_MS
            await tx.execute(
                "INSERT INTO human_auth_sessions "
                "(key_id,generation,principal_id,secret_digest,grants,expires_at_ms) "
                "VALUES(?,?,?,?,?,?)",
                (
                    key_id,
                    self.generation,
                    principal_id,
                    digest,
                    _GRANTS.dump_json(grants).decode("utf-8"),
                    expires_at_ms,
                ),
            )
        return IssuedSession(f"mrh_{key_id}_{secret}", key_id, expires_at_ms // 1000)

    async def authenticate(self, key_id: str, secret: str) -> StoredSession | None:
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        async with self.db.transaction(capacity_lock=True) as tx:
            await self._require_generation(tx)
            now = await _now_ms(tx)
            row = await tx.fetchone(
                "SELECT key_id,principal_id,secret_digest,grants FROM human_auth_sessions "
                "WHERE key_id=? AND generation=? AND expires_at_ms>? AND revoked=0",
                (key_id, self.generation, now),
            )
            expected = str(row["secret_digest"]) if row is not None else _DUMMY_DIGEST
            valid = hmac.compare_digest(digest, expected)
            if row is None or not valid:
                return None
            return StoredSession(
                str(row["principal_id"]),
                str(row["key_id"]),
                _GRANTS.validate_json(str(row["grants"])),
            )

    async def revoke(self, key_id: str) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            await tx.execute("UPDATE human_auth_sessions SET revoked=1 WHERE key_id=?", (key_id,))

    async def _require_session_capacity(self, tx: Tx, now: int) -> None:
        row = await tx.fetchone(
            "SELECT COUNT(*) AS count FROM human_auth_sessions WHERE expires_at_ms>?", (now,)
        )
        if row is not None and int(row["count"]) >= 10_000:
            raise _capacity()

    async def prune(self) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            await self._prune(tx, await _now_ms(tx))

    async def _prune(self, tx: Tx, now: int) -> None:
        await tx.execute("DELETE FROM human_auth_logins WHERE expires_at_ms<=?", (now,))
        await tx.execute("DELETE FROM human_auth_sessions WHERE expires_at_ms<=?", (now,))
