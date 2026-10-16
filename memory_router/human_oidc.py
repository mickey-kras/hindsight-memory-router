from __future__ import annotations

import json
import time
from typing import cast
from urllib.parse import urlencode

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, KeySetSerialization
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import HttpError
from .human_auth_config import HumanAuthConfig, https_url


class ProviderMetadata(BaseModel):
    model_config = ConfigDict(strict=True)

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    code_challenge_methods_supported: list[str]
    response_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]

    @field_validator("authorization_endpoint", "token_endpoint", "jwks_uri")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return https_url(value)


class IdentityClaims(BaseModel):
    model_config = ConfigDict(strict=True)

    iss: str
    sub: str = Field(min_length=1, max_length=255)
    aud: str | list[str]
    exp: int
    iat: int
    nbf: int | None = None
    azp: str | None = None
    nonce: str


class TokenResponse(BaseModel):
    model_config = ConfigDict(strict=True)

    id_token: str = Field(min_length=1, max_length=32768)


def invalid_identity() -> HttpError:
    return HttpError(401, "human_login_failed", "human authentication failed; sign in again")


class HumanOidc:
    def __init__(self, config: HumanAuthConfig, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self.client = client or httpx.AsyncClient(
            timeout=10, follow_redirects=False, trust_env=False
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def _fetch(
        self, url: str, *, data: dict[str, str] | None = None, maximum: int = 65536
    ) -> bytes:
        https_url(url)
        try:
            async with self.client.stream(
                "GET" if data is None else "POST",
                url,
                data=data,
                headers={"accept": "application/json", "accept-encoding": "identity"},
                follow_redirects=False,
                timeout=10,
            ) as response:
                if response.status_code == 429 or response.status_code >= 500:
                    raise HttpError(
                        503, "human_identity_unavailable", "identity provider unavailable"
                    )
                if response.status_code != 200:
                    raise invalid_identity()
                if (
                    response.headers.get("content-encoding", "identity").strip().lower()
                    != "identity"
                ):
                    raise invalid_identity()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > maximum:
                        raise invalid_identity()
                return bytes(body)
        except httpx.HTTPError:
            raise HttpError(
                503, "human_identity_unavailable", "identity provider unavailable"
            ) from None

    async def metadata(self) -> ProviderMetadata:
        try:
            metadata = ProviderMetadata.model_validate_json(
                await self._fetch(
                    self.config.issuer.rstrip("/") + "/.well-known/openid-configuration"
                )
            )
            if (
                metadata.issuer != self.config.issuer
                or "S256" not in metadata.code_challenge_methods_supported
                or "code" not in metadata.response_types_supported
                or "RS256" not in metadata.id_token_signing_alg_values_supported
            ):
                raise invalid_identity()
            return metadata
        except ValueError:
            raise invalid_identity() from None

    async def authorization_url(
        self, *, redirect_uri: str, state: str, challenge: str, nonce: str
    ) -> str:
        metadata = await self.metadata()
        return (
            metadata.authorization_endpoint
            + "?"
            + urlencode(
                {
                    "response_type": "code",
                    "client_id": self.config.client_id,
                    "redirect_uri": redirect_uri,
                    "scope": "openid",
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        )

    async def identity(self, *, code: str, verifier: str, redirect_uri: str, nonce: str) -> str:
        metadata = await self.metadata()
        try:
            response = TokenResponse.model_validate_json(
                await self._fetch(
                    metadata.token_endpoint,
                    data={
                        "grant_type": "authorization_code",
                        "client_id": self.config.client_id,
                        "redirect_uri": redirect_uri,
                        "code": code,
                        "code_verifier": verifier,
                    },
                )
            )
            raw_keys = await self._fetch(metadata.jwks_uri, maximum=262144)
            keys_value: object = json.loads(raw_keys)
            if not isinstance(keys_value, dict) or not isinstance(keys_value.get("keys"), list):
                raise invalid_identity()
            keys = KeySet.import_key_set(cast(KeySetSerialization, keys_value))
            token = jwt.decode(response.id_token, keys, algorithms=["RS256"])
            claims = IdentityClaims.model_validate(token.claims)
            now = int(time.time())
            if (
                claims.iss != self.config.issuer
                or claims.aud not in (self.config.client_id, [self.config.client_id])
                or (claims.azp is not None and claims.azp != self.config.client_id)
                or claims.nonce != nonce
                or claims.exp <= now
                or claims.iat > now
                or claims.iat >= claims.exp
                or (claims.nbf is not None and claims.nbf > now)
            ):
                raise invalid_identity()
            return claims.sub
        except (JoseError, ValueError, TypeError, KeyError):
            raise invalid_identity() from None
