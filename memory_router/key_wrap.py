from __future__ import annotations

import asyncio
import base64
import binascii
import json
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Literal, Protocol
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pydantic import BaseModel, ConfigDict, StrictStr, ValidationError

from .envelope import KEY_WRAP_TOKEN_RE, decode_public_key
from .errors import HttpError

RSA_OAEP_KEY_WRAP = "RSA-OAEP-SHA256"
SIDECAR_KEY_WRAP = "WRAP-SIDECAR"
DEFAULT_SIDECAR_TIMEOUT_MS = 5_000
MAX_SIDECAR_TIMEOUT_MS = 60_000
DEFAULT_SIDECAR_NAME = "https-sidecar"
DEFAULT_SIDECAR_WRAPPED_KEY_BYTES = 512
MAX_WRAP_RESPONSE_BYTES = 65_536
MAX_WRAPPED_KEY_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class WrapProviderInfo:
    name: str
    version: int


class WrapProvider(Protocol):
    key_wrap: str
    wrapped_key_bytes: int

    def envelope_provider(self) -> WrapProviderInfo | None: ...

    async def wrap(self, dek: bytes) -> bytes: ...

    async def close(self) -> None: ...


def provider_envelope_metadata(info: WrapProviderInfo | None) -> dict[str, object] | None:
    if info is None:
        return None
    return {"name": info.name, "version": info.version}


class RsaOaepWrapProvider:
    def __init__(self, public_key: str) -> None:
        key = decode_public_key(public_key)
        self._key = key
        self.key_wrap = RSA_OAEP_KEY_WRAP
        self.wrapped_key_bytes = key.key_size // 8

    def envelope_provider(self) -> WrapProviderInfo | None:
        return None

    async def wrap(self, dek: bytes) -> bytes:
        return self._key.encrypt(
            dek,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    async def close(self) -> None:
        return None


class WrapSidecarError(HttpError):
    def __init__(self, kind: Literal["timeout", "http", "invalid-response", "network"]) -> None:
        code = {
            "timeout": "quarantine_wrap_sidecar_timeout",
            "http": "quarantine_wrap_sidecar_http_error",
            "invalid-response": "quarantine_wrap_sidecar_invalid_response",
            "network": "quarantine_wrap_sidecar_unavailable",
        }[kind]
        message = {
            "timeout": "Quarantine wrap sidecar timed out",
            "http": "Quarantine wrap sidecar request failed",
            "invalid-response": "Quarantine wrap sidecar returned an invalid response",
            "network": "Quarantine wrap sidecar is unavailable",
        }[kind]
        super().__init__(504 if kind == "timeout" else 502, code, message)
        self.kind = kind


class _WrapSidecarResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    wrapped_key_b64: StrictStr


class SidecarWrapProvider:
    def __init__(
        self,
        base_url: str,
        token: str | None,
        timeout_ms: int,
        name: str,
        version: int,
        wrapped_key_bytes: int,
    ) -> None:
        if not isinstance(name, str) or not KEY_WRAP_TOKEN_RE.fullmatch(name):
            raise RuntimeError("QUARANTINE_WRAP_SIDECAR_NAME must match [A-Za-z0-9._-]{1,64}")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise RuntimeError("QUARANTINE_WRAP_SIDECAR_VERSION must be >= 1")
        if not 0 < timeout_ms <= MAX_SIDECAR_TIMEOUT_MS:
            raise RuntimeError(
                f"QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS must be between 1 and {MAX_SIDECAR_TIMEOUT_MS}"
            )
        if not 0 < wrapped_key_bytes <= MAX_WRAPPED_KEY_BYTES:
            raise RuntimeError("QUARANTINE_WRAP_SIDECAR_WRAPPED_KEY_BYTES is out of range")
        assert_sidecar_url(base_url)
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout_ms = timeout_ms
        self.key_wrap = SIDECAR_KEY_WRAP
        self.wrapped_key_bytes = wrapped_key_bytes
        self._info = WrapProviderInfo(name, version)
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(timeout_ms / 1000.0))

    def envelope_provider(self) -> WrapProviderInfo | None:
        return self._info

    async def close(self) -> None:
        await self.client.aclose()

    async def wrap(self, dek: bytes) -> bytes:
        headers = {"content-type": "application/json"}
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"
        request = self.client.build_request(
            "POST",
            f"{self.base_url}/wrap",
            headers=headers,
            json={"dek_b64": base64.b64encode(dek).decode("ascii")},
        )
        response: httpx.Response | None = None
        try:
            async with asyncio.timeout(self.timeout_ms / 1000.0):
                response = await self.client.send(request, stream=True)
                if not response.is_success:
                    raise WrapSidecarError("http")
                return self._parse_wrapped(await _read_bounded(response))
        except (TimeoutError, httpx.TimeoutException) as exc:
            raise WrapSidecarError("timeout") from exc
        except WrapSidecarError:
            raise
        except httpx.HTTPError as exc:
            raise WrapSidecarError("network") from exc
        finally:
            if response is not None:
                await response.aclose()

    def _parse_wrapped(self, raw: bytes) -> bytes:
        try:
            parsed = _WrapSidecarResponse.model_validate(json.loads(raw))
            wrapped = base64.b64decode(parsed.wrapped_key_b64, validate=True)
        except (ValidationError, ValueError, binascii.Error) as exc:
            raise WrapSidecarError("invalid-response") from exc
        if not wrapped or len(wrapped) > self.wrapped_key_bytes:
            raise WrapSidecarError("invalid-response")
        return wrapped


async def _read_bounded(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > MAX_WRAP_RESPONSE_BYTES:
            raise WrapSidecarError("invalid-response")
        chunks.append(chunk)
    return b"".join(chunks)


def assert_sidecar_url(base_url: str) -> None:
    parsed = urlsplit(base_url)
    host = parsed.hostname or ""
    if parsed.scheme == "https" and host:
        return
    loopback = host == "localhost"
    if not loopback:
        try:
            loopback = ip_address(host).is_loopback
        except ValueError:
            loopback = False
    if parsed.scheme == "http" and loopback:
        return
    raise RuntimeError(
        "QUARANTINE_WRAP_SIDECAR_URL must use https (http allowed for loopback only)"
    )
