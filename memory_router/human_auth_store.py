from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import TypeAdapter

from .db import Database, Tx
from .errors import HttpError
from .human_auth_config import HumanAuthConfig
from .principals import PrincipalGrant

_GRANTS = TypeAdapter(tuple[PrincipalGrant, ...])
_DUMMY_DIGEST = hashlib.sha256(b"human-session:unknown").hexdigest()
_LOGIN_TTL_MS = 300_000
_SESSION_TTL_MS = 3_600_000
# Superseded access tokens of a refreshed session stay valid briefly for in-flight requests.
_ROTATION_GRACE_MS = 60_000
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS human_auth_policy "
    "(id INTEGER PRIMARY KEY, generation TEXT NOT NULL, activation_epoch BIGINT NOT NULL DEFAULT 1)",
    "CREATE TABLE IF NOT EXISTS human_auth_logins "
    "(transaction_id TEXT PRIMARY KEY, generation TEXT NOT NULL, activation_epoch BIGINT NOT NULL, "
    "state TEXT NOT NULL, "
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
    "CREATE TABLE IF NOT EXISTS human_auth_families "
    "(family_id TEXT PRIMARY KEY, generation TEXT NOT NULL, principal_id TEXT NOT NULL, "
    "grants TEXT NOT NULL, idle_expires_at_ms BIGINT NOT NULL, "
    "absolute_expires_at_ms BIGINT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
    "CREATE INDEX IF NOT EXISTS idx_human_auth_families_principal "
    "ON human_auth_families(principal_id, absolute_expires_at_ms)",
    "CREATE TABLE IF NOT EXISTS human_auth_refresh_tokens "
    "(key_id TEXT PRIMARY KEY, family_id TEXT NOT NULL, secret_digest TEXT NOT NULL, "
    "used INTEGER NOT NULL DEFAULT 0)",
    "CREATE INDEX IF NOT EXISTS idx_human_auth_refresh_tokens_family "
    "ON human_auth_refresh_tokens(family_id)",
)


@dataclass(frozen=True, slots=True)
class LoginTransaction:
    activation_epoch: int
    redirect_uri: str
    nonce: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RefreshPolicy:
    idle_ms: int
    absolute_ms: int


def refresh_policy(config: HumanAuthConfig) -> RefreshPolicy | None:
    idle, absolute = config.session_idle_seconds, config.session_absolute_seconds
    if idle is None or absolute is None:
        return None
    return RefreshPolicy(idle * 1000, absolute * 1000)


@dataclass(frozen=True, slots=True)
class IssuedSession:
    token: str = field(repr=False)
    key_id: str
    expires_at: int
    refresh_token: str | None = field(default=None, repr=False)
    principal_id: str = ""
    grants: tuple[PrincipalGrant, ...] = ()


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


def _secret() -> tuple[str, str, str]:
    key_id, secret = secrets.token_hex(16), secrets.token_hex(32)
    return key_id, secret, hashlib.sha256(secret.encode("ascii")).hexdigest()


class RefreshRejected(Exception):
    """Refresh failed after the store committed any resulting revocation."""

    def __init__(self, *, reuse: bool) -> None:
        super().__init__("interactive login is required")
        self.reuse = reuse


def _capacity() -> HttpError:
    return HttpError(
        429, "human_auth_capacity", "human login capacity exhausted", {"retry-after": "60"}
    )


class HumanAuthStore:
    def __init__(self, db: Database, generation: str, refresh: RefreshPolicy | None = None) -> None:
        self.db = db
        self.generation = generation
        self.refresh_policy = refresh

    async def initialize(self, *, check_generation: bool = True) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            for statement in _SCHEMA:
                await tx.execute(statement)
            if not await tx.column_exists("human_auth_sessions", "family_id"):
                await tx.execute("ALTER TABLE human_auth_sessions ADD COLUMN family_id TEXT")
            await tx.execute(
                "CREATE INDEX IF NOT EXISTS idx_human_auth_sessions_family "
                "ON human_auth_sessions(family_id)"
            )
            await tx.execute(
                "INSERT INTO human_auth_policy(id,generation) VALUES(1,?) "
                "ON CONFLICT(id) DO NOTHING",
                (self.generation,),
            )
            if check_generation:
                await self._require_generation(tx)

    async def _require_generation(self, tx: Tx) -> int:
        row = await tx.fetchone(
            "SELECT generation,activation_epoch FROM human_auth_policy WHERE id=1"
        )
        if row is None or row["generation"] != self.generation:
            raise _unavailable()
        return int(row["activation_epoch"])

    async def require_generation(self) -> int:
        async with self.db.transaction(capacity_lock=True) as tx:
            return await self._require_generation(tx)

    async def activate(self) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            await tx.execute(
                "UPDATE human_auth_policy SET generation=?,activation_epoch=activation_epoch+1 WHERE id=1",
                (self.generation,),
            )
            await tx.execute("DELETE FROM human_auth_logins")
            # Keep unexpired rows counted against caps even after revocation.
            await tx.execute("UPDATE human_auth_sessions SET revoked=1")
            await tx.execute("UPDATE human_auth_families SET revoked=1")
            await self._prune(tx, await _now_ms(tx))

    async def create_login(
        self, *, state: str, challenge: str, redirect_uri: str, nonce: str
    ) -> str:
        transaction_id = secrets.token_urlsafe(32)
        async with self.db.transaction(capacity_lock=True) as tx:
            activation_epoch = await self._require_generation(tx)
            now = await _now_ms(tx)
            await self._prune(tx, now)
            await self._require_session_capacity(tx, now)
            row = await tx.fetchone("SELECT COUNT(*) AS count FROM human_auth_logins")
            if row is not None and int(row["count"]) >= 1000:
                raise _capacity()
            await tx.execute(
                "INSERT INTO human_auth_logins "
                "(transaction_id,generation,activation_epoch,state,challenge,redirect_uri,nonce,expires_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    transaction_id,
                    self.generation,
                    activation_epoch,
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
            activation_epoch = await self._require_generation(tx)
            now = await _now_ms(tx)
            await self._require_session_capacity(tx, now)
            row = await tx.fetchone(
                "SELECT state,challenge,redirect_uri,nonce FROM human_auth_logins "
                "WHERE transaction_id=? AND generation=? AND activation_epoch=? AND expires_at_ms>?",
                (transaction_id, self.generation, activation_epoch, now),
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
            result = LoginTransaction(activation_epoch, str(row["redirect_uri"]), str(row["nonce"]))
        return result

    async def cancel_login(self, transaction_id: str) -> None:
        async with self.db.transaction(capacity_lock=True) as tx:
            await tx.execute(
                "DELETE FROM human_auth_logins WHERE transaction_id=? AND generation=?",
                (transaction_id, self.generation),
            )

    async def issue(
        self, *, activation_epoch: int, principal_id: str, grants: tuple[PrincipalGrant, ...]
    ) -> IssuedSession:
        async with self.db.transaction(capacity_lock=True) as tx:
            if await self._require_generation(tx) != activation_epoch:
                raise _invalid_login()
            now = await _now_ms(tx)
            await self._prune(tx, now)
            row = await tx.fetchone(
                "SELECT COUNT(*) AS total, "
                "COALESCE(SUM(CASE WHEN principal_id=? THEN 1 ELSE 0 END),0) AS personal "
                "FROM human_auth_sessions",
                (principal_id,),
            )
            families = await tx.fetchone(
                "SELECT COUNT(*) AS personal FROM human_auth_families WHERE principal_id=?",
                (principal_id,),
            )
            if (
                row is not None and (int(row["total"]) >= 10_000 or int(row["personal"]) >= 20)
            ) or (families is not None and int(families["personal"]) >= 20):
                raise _capacity()
            family_id: str | None = None
            refresh_token: str | None = None
            expires_at_ms = now + _SESSION_TTL_MS
            if (policy := self.refresh_policy) is not None:
                family_id = secrets.token_hex(16)
                absolute = now + policy.absolute_ms
                expires_at_ms = min(expires_at_ms, absolute)
                await tx.execute(
                    "INSERT INTO human_auth_families "
                    "(family_id,generation,principal_id,grants,idle_expires_at_ms,"
                    "absolute_expires_at_ms) VALUES(?,?,?,?,?,?)",
                    (
                        family_id,
                        self.generation,
                        principal_id,
                        _GRANTS.dump_json(grants).decode("utf-8"),
                        min(now + policy.idle_ms, absolute),
                        absolute,
                    ),
                )
                refresh_token = await self._insert_refresh_token(tx, family_id)
            token, key_id = await self._insert_access(
                tx, principal_id, grants, expires_at_ms, family_id
            )
        return IssuedSession(
            token, key_id, expires_at_ms // 1000, refresh_token, principal_id, grants
        )

    async def _insert_refresh_token(self, tx: Tx, family_id: str) -> str:
        key_id, secret, digest = _secret()
        await tx.execute(
            "INSERT INTO human_auth_refresh_tokens(key_id,family_id,secret_digest) VALUES(?,?,?)",
            (key_id, family_id, digest),
        )
        return f"mrr_{key_id}_{secret}"

    async def _insert_access(
        self,
        tx: Tx,
        principal_id: str,
        grants: tuple[PrincipalGrant, ...],
        expires_at_ms: int,
        family_id: str | None,
    ) -> tuple[str, str]:
        key_id, secret, digest = _secret()
        await tx.execute(
            "INSERT INTO human_auth_sessions "
            "(key_id,generation,principal_id,secret_digest,grants,expires_at_ms,family_id) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                key_id,
                self.generation,
                principal_id,
                digest,
                _GRANTS.dump_json(grants).decode("utf-8"),
                expires_at_ms,
                family_id,
            ),
        )
        return f"mrh_{key_id}_{secret}", key_id

    async def _refresh_row(self, tx: Tx, key_id: str, secret: str) -> dict[str, Any] | None:
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        row = await tx.fetchone(
            "SELECT t.family_id,t.secret_digest,t.used,f.principal_id,f.grants,f.revoked,"
            "f.idle_expires_at_ms,f.absolute_expires_at_ms "
            "FROM human_auth_refresh_tokens t "
            "JOIN human_auth_families f ON f.family_id=t.family_id "
            "WHERE t.key_id=? AND f.generation=?",
            (key_id, self.generation),
        )
        expected = str(row["secret_digest"]) if row is not None else _DUMMY_DIGEST
        valid = hmac.compare_digest(digest, expected)
        return row if row is not None and valid else None

    async def refresh(
        self,
        key_id: str,
        secret: str,
        authorize: Callable[[str, tuple[PrincipalGrant, ...]], tuple[PrincipalGrant, ...] | None],
    ) -> IssuedSession:
        """Rotate a refresh token once; reuse or lost permission revokes the whole session."""
        policy = self.refresh_policy
        if policy is None:
            raise RefreshRejected(reuse=False)
        async with self.db.transaction(capacity_lock=True) as tx:
            await self._require_generation(tx)
            now = await _now_ms(tx)
            row = await self._refresh_row(tx, key_id, secret)
            if row is None:
                raise RefreshRejected(reuse=False)
            family_id = str(row["family_id"])
            absolute = int(row["absolute_expires_at_ms"])
            if int(row["used"]):
                # Commit the revocation before rejecting known reuse.
                await self._revoke_family(tx, family_id, now)
                rejected = RefreshRejected(reuse=True)
            elif int(row["revoked"]) or min(int(row["idle_expires_at_ms"]), absolute) <= now:
                raise RefreshRejected(reuse=False)
            elif (
                grants := authorize(
                    str(row["principal_id"]), _GRANTS.validate_json(str(row["grants"]))
                )
            ) is None:
                await self._revoke_family(tx, family_id, now)
                rejected = RefreshRejected(reuse=False)
            else:
                await self._require_session_capacity(tx, now)
                await tx.execute(
                    "UPDATE human_auth_refresh_tokens SET used=1 WHERE key_id=?", (key_id,)
                )
                grace = now + _ROTATION_GRACE_MS
                await tx.execute(
                    "UPDATE human_auth_sessions SET expires_at_ms=? "
                    "WHERE family_id=? AND expires_at_ms>?",
                    (grace, family_id, grace),
                )
                await tx.execute(
                    "UPDATE human_auth_families SET idle_expires_at_ms=? WHERE family_id=?",
                    (min(now + policy.idle_ms, absolute), family_id),
                )
                refresh_token = await self._insert_refresh_token(tx, family_id)
                principal_id = str(row["principal_id"])
                expires_at_ms = min(now + _SESSION_TTL_MS, absolute)
                token, access_key = await self._insert_access(
                    tx, principal_id, grants, expires_at_ms, family_id
                )
                return IssuedSession(
                    token, access_key, expires_at_ms // 1000, refresh_token, principal_id, grants
                )
        raise rejected

    async def sign_out_refresh(self, key_id: str, secret: str) -> bool:
        async with self.db.transaction(capacity_lock=True) as tx:
            await self._require_generation(tx)
            row = await self._refresh_row(tx, key_id, secret)
            if row is None:
                return False
            await self._revoke_family(tx, str(row["family_id"]), await _now_ms(tx))
        return True

    async def _revoke_family(self, tx: Tx, family_id: str, now: int) -> None:
        # Keep revoked sessions for at most one access lifetime: they still count against
        # caps and detect reuse, but cannot block new logins for the full idle window.
        await tx.execute(
            "UPDATE human_auth_families SET revoked=1, idle_expires_at_ms=CASE "
            "WHEN idle_expires_at_ms>? THEN ? ELSE idle_expires_at_ms END WHERE family_id=?",
            (now + _SESSION_TTL_MS, now + _SESSION_TTL_MS, family_id),
        )
        await tx.execute("UPDATE human_auth_sessions SET revoked=1 WHERE family_id=?", (family_id,))

    async def authenticate(self, key_id: str, secret: str) -> StoredSession | None:
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        async with self.db.transaction() as tx:
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
        """Revoke an access or refresh key ID and every credential of its session."""
        async with self.db.transaction(capacity_lock=True) as tx:
            await tx.execute("UPDATE human_auth_sessions SET revoked=1 WHERE key_id=?", (key_id,))
            row = await tx.fetchone(
                "SELECT family_id FROM human_auth_sessions WHERE key_id=? AND family_id IS NOT NULL "
                "UNION SELECT family_id FROM human_auth_refresh_tokens WHERE key_id=?",
                (key_id, key_id),
            )
            if row is not None:
                await self._revoke_family(tx, str(row["family_id"]), await _now_ms(tx))

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
        await tx.execute(
            "DELETE FROM human_auth_families WHERE idle_expires_at_ms<=? OR absolute_expires_at_ms<=?",
            (now, now),
        )
        await tx.execute(
            "DELETE FROM human_auth_refresh_tokens WHERE NOT EXISTS "
            "(SELECT 1 FROM human_auth_families f WHERE f.family_id=human_auth_refresh_tokens.family_id)"
        )
