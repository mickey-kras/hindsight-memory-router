from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import secrets
from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .errors import HttpError
from .human_auth_config import HumanAuthConfig
from .human_auth_store import HumanAuthStore
from .human_oidc import HumanOidc, invalid_identity
from .lifecycle import cleanup_result
from .logging import log_event
from .principals import Authentication, PrincipalGrant, PrincipalResolver, PrincipalSession
from .rate_limit import Bucket, ConcurrencyLimiter, RateLimiter

logger = logging.getLogger(__name__)
HUMAN_TOKEN = re.compile(r"^Bearer mrh_([0-9a-f]{32})_([0-9a-f]{64})$")
_RANDOM_VALUE = r"^[A-Za-z0-9_-]{43}$"
_REDIRECT = re.compile(r"^http://127\.0\.0\.1:([1-9]\d{0,4})/callback$", re.ASCII)
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class StartLogin(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    redirect_uri: str = Field(max_length=128)
    state: str = Field(pattern=_RANDOM_VALUE, min_length=43, max_length=43)
    code_challenge: str = Field(pattern=_RANDOM_VALUE, min_length=43, max_length=43)


class ExchangeLogin(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    transaction_id: str = Field(pattern=_RANDOM_VALUE, min_length=43, max_length=43)
    code: str = Field(min_length=1, max_length=4096)
    state: str = Field(pattern=_RANDOM_VALUE, min_length=43, max_length=43)
    code_verifier: str = Field(pattern=_RANDOM_VALUE, min_length=43, max_length=43)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


async def _body(request: Request) -> object:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 8192:
            raise HttpError(413, "payload_too_large", "human login body exceeds 8 KiB")
    try:
        value: object = json.loads(body, object_pairs_hook=_unique_object)
        return value
    except (ValueError, RecursionError):
        raise HttpError(400, "invalid_human_login", "invalid human login request") from None


def unavailable() -> HttpError:
    return HttpError(503, "human_auth_unavailable", "human authentication unavailable")


class HumanAuth:
    def __init__(
        self,
        config: HumanAuthConfig,
        store: HumanAuthStore,
        resolver: PrincipalResolver,
        limiter: RateLimiter,
        concurrency: ConcurrencyLimiter,
        oidc: HumanOidc | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.resolver = resolver
        self.limiter = limiter
        self.concurrency = concurrency
        self.oidc = oidc or HumanOidc(config)

    async def close(self) -> None:
        await self.oidc.close()

    async def _bounded[T](self, operation: Callable[[], Awaitable[T]]) -> T:
        async def timed() -> T:
            async with asyncio.timeout(30):
                return await operation()

        return await self.concurrency.run("human-auth:provider", 8, timed)

    async def authenticate(self, authorization: str) -> Authentication:
        match = HUMAN_TOKEN.fullmatch(authorization)
        if match is None:
            return Authentication("invalid-format")
        try:
            stored = await self.store.authenticate(match[1], match[2])
        except HttpError:
            raise
        except Exception as exc:
            self._log_unavailable(exc)
            raise unavailable() from None
        if stored is None:
            return Authentication("unknown-key")
        principal = self.resolver.registry.principals.get(stored.principal_id)
        if principal is None or principal.source != "human":
            return Authentication("revoked")
        current = {(grant.bank, scope) for grant in principal.grants for scope in grant.scopes}
        grants = tuple(
            PrincipalGrant(bank=grant.bank, scopes=scopes)
            for grant in stored.grants
            if (scopes := [scope for scope in grant.scopes if (grant.bank, scope) in current])
        )
        return Authentication(
            "ok",
            PrincipalSession(
                stored.principal_id,
                stored.key_id,
                grants,
                self.resolver._limits_for(principal),
                "human",
            ),
        )

    @staticmethod
    def _log_unavailable(error: Exception) -> None:
        log_event(
            logger,
            "error",
            "request_failed",
            operation="authenticate",
            error_kind="storage",
            error=error,
            outcome="failed",
            http_status=503,
        )

    async def dispatch(self, request: Request, operation: str) -> JSONResponse:
        try:
            if request.method != "POST" or operation not in {"start", "exchange", "sign-out"}:
                raise HttpError(404, "not_found", "not found")
            await self.limiter.consume_many(
                [
                    Bucket(f"human-auth:{operation}", 20 if operation == "start" else 60, 60000),
                ]
            )
            if operation == "sign-out":
                result = await self.authenticate(request.headers.get("authorization", ""))
                if result.session is None:
                    raise invalid_identity()
                await self.store.revoke(result.session.key_id)
                return JSONResponse({"signed_out": True}, headers=_NO_STORE)
            value = await _body(request)
            if operation == "start":
                return JSONResponse(
                    await self.start(StartLogin.model_validate(value)), headers=_NO_STORE
                )
            return JSONResponse(
                await self.exchange(ExchangeLogin.model_validate(value)), headers=_NO_STORE
            )
        except ValidationError:
            error = HttpError(400, "invalid_human_login", "invalid human login request")
        except HttpError as exc:
            error = exc
        except Exception as exc:
            self._log_unavailable(exc)
            error = unavailable()
        return JSONResponse(
            error.body(), status_code=error.status, headers={**error.headers, **_NO_STORE}
        )

    async def start(self, login: StartLogin) -> dict[str, str]:
        matched = _REDIRECT.fullmatch(login.redirect_uri)
        if matched is None or int(matched[1]) > 65535:
            raise HttpError(400, "invalid_human_login", "invalid loopback redirect")

        async def begin() -> dict[str, str]:
            nonce = secrets.token_urlsafe(32)
            transaction_id = await self.store.create_login(
                state=login.state,
                challenge=login.code_challenge,
                redirect_uri=login.redirect_uri,
                nonce=nonce,
            )
            try:
                url = await self.oidc.authorization_url(
                    redirect_uri=login.redirect_uri,
                    state=login.state,
                    challenge=login.code_challenge,
                    nonce=nonce,
                )
            except BaseException as error:
                if (
                    cleanup_error := await cleanup_result(self.store.cancel_login(transaction_id))
                ) is not None:
                    error.__cause__ = cleanup_error
                raise
            return {"transaction_id": transaction_id, "authorization_url": url}

        return await self._bounded(begin)

    async def exchange(self, login: ExchangeLogin) -> dict[str, object]:
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(login.code_verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        transaction = await self.store.claim_login(
            login.transaction_id, state=login.state, challenge=challenge
        )
        subject = await self._bounded(
            lambda: self.oidc.identity(
                code=login.code,
                verifier=login.code_verifier,
                redirect_uri=transaction.redirect_uri,
                nonce=transaction.nonce,
            )
        )
        principal_id = self.config.subjects.get(subject)
        if principal_id is None:
            raise invalid_identity()
        principal = self.resolver.registry.principals[principal_id]
        issued = await self.store.issue(
            principal_id=principal_id,
            grants=tuple(principal.grants),
            activation_epoch=transaction.activation_epoch,
        )
        return {
            "token": issued.token,
            "token_type": "Bearer",  # nosec B105 - OAuth token type, not a credential
            "principal_id": principal_id,
            "grants": [grant.model_dump() for grant in principal.grants],
            "expires_at": issued.expires_at,
        }
