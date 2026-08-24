from __future__ import annotations

import asyncio
import json
import math
from typing import Any, Literal, cast
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr, ValidationError

from .canonical import canonical_json
from .errors import HttpError
from .models import RecallResponse
from .observability import current_request_id

DEFAULT_HINDSIGHT_TIMEOUT_MS = 10_000
DEFAULT_HINDSIGHT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_HINDSIGHT_JSON_DEPTH = 64
_UNSUPPORTED_FACADE_FEATURES = (
    "mcp",
    "bank_llm_health",
    "file_upload_api",
    "document_export_api",
    "document_import_api",
)


class _HindsightHealthResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    status: Literal["healthy"]
    database: Literal["connected"]
    db_acquire_ms: float | None = None
    db_pool_waiting: int | None = None


class _HindsightFeaturesInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    observations: StrictBool
    mcp: StrictBool
    worker: StrictBool
    bank_config_api: StrictBool
    bank_llm_health: StrictBool
    file_upload_api: StrictBool
    document_export_api: StrictBool
    document_import_api: StrictBool
    audit_log: StrictBool
    llm_trace: StrictBool
    store_document_text: StrictBool


class _HindsightVersionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    api_version: StrictStr
    features: _HindsightFeaturesInfo


class HindsightGatewayError(HttpError):
    def __init__(
        self,
        kind: Literal["timeout", "http", "invalid-response", "network", "response-too-large"],
        *,
        upstream_status: int | None = None,
        operation: str | None = None,
        method: str | None = None,
        timeout_ms: int | None = None,
        client_status: int | None = None,
    ) -> None:
        code = {
            "timeout": "hindsight_timeout",
            "http": "hindsight_http_error",
            "invalid-response": "hindsight_invalid_response",
            "network": "hindsight_unavailable",
            "response-too-large": "hindsight_response_too_large",
        }[kind]
        message = {
            "timeout": "Upstream memory service timed out",
            "http": "Upstream memory service request failed",
            "invalid-response": "Upstream memory service returned an invalid response",
            "network": "Upstream memory service is unavailable",
            "response-too-large": "Upstream memory service response exceeded the size limit",
        }[kind]
        status = client_status if client_status is not None else (504 if kind == "timeout" else 502)
        super().__init__(status, code, message)
        self.kind = kind
        self.upstream_status = upstream_status
        self.context = {"operation": operation, "method": method, "timeout_ms": timeout_ms}

    def details(self) -> dict[str, Any]:
        details: dict[str, Any] = {"error_kind": self.kind, "status": self.status}
        if self.upstream_status is not None:
            details["upstream_status"] = self.upstream_status
        for key in ("operation", "method", "timeout_ms"):
            if self.context[key] is not None:
                details[key] = self.context[key]
        return details


def _assert_response_depth(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_HINDSIGHT_JSON_DEPTH:
            raise ValueError("upstream JSON nesting depth exceeds limit")
        if isinstance(current, dict):
            stack.extend((entry, depth + 1) for entry in current.values())
        elif isinstance(current, list):
            stack.extend((entry, depth + 1) for entry in current)


def _assert_finite_numbers(value: Any) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, float) and not math.isfinite(current):
            raise ValueError("upstream JSON contains a non-finite number")
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


class HindsightGateway:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        timeout_ms: int = DEFAULT_HINDSIGHT_TIMEOUT_MS,
        max_response_bytes: int = DEFAULT_HINDSIGHT_MAX_RESPONSE_BYTES,
    ) -> None:
        if timeout_ms <= 0:
            raise RuntimeError("Hindsight timeout must be a positive integer")
        if max_response_bytes <= 0:
            raise RuntimeError("Hindsight response size limit must be a positive integer")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_ms = timeout_ms
        self.max_response_bytes = max_response_bytes
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(timeout_ms / 1000.0))

    async def close(self) -> None:
        await self.client.aclose()

    async def health(self) -> dict[str, Any]:
        value = await self._request("health", "GET", "/health")
        try:
            response = _HindsightHealthResponse.model_validate(value)
        except ValidationError as exc:
            raise HindsightGatewayError(
                "invalid-response", operation="health", method="GET"
            ) from exc
        return response.model_dump(exclude_none=True)

    async def version(self) -> dict[str, Any]:
        value = await self._request("version", "GET", "/version")
        try:
            response = _HindsightVersionResponse.model_validate(value)
        except ValidationError as exc:
            raise HindsightGatewayError(
                "invalid-response", operation="version", method="GET"
            ) from exc
        facade = response.model_dump()
        for feature in _UNSUPPORTED_FACADE_FEATURES:
            facade["features"][feature] = False
        return facade

    async def retain(self, bank_id: str, body: dict[str, Any]) -> Any:
        return await self._request(
            "retain", "POST", f"/v1/default/banks/{quote(bank_id, safe='')}/memories", body
        )

    async def recall(self, bank_id: str, body: dict[str, Any]) -> dict[str, Any]:
        value = await self._request(
            "recall", "POST", f"/v1/default/banks/{quote(bank_id, safe='')}/memories/recall", body
        )
        try:
            _assert_response_depth(value)
            RecallResponse.model_validate(value)
            for result in value.get("results", []):
                canonical_json({"id": result["id"], "text": result["text"]})
        except (ValidationError, ValueError, RecursionError) as exc:
            raise HindsightGatewayError(
                "invalid-response", operation="recall", method="POST"
            ) from exc
        return cast(dict[str, Any], value)

    async def openclaw_request(
        self, operation: str, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        """Forward one allowlisted OpenClaw-facing Hindsight operation."""
        return await self._request(operation, method, path, body, preserve_http_status=True)

    async def invalidate_memory(self, bank_id: str, memory_id: str, reason: str) -> None:
        await self._request(
            "invalidate_memory",
            "PATCH",
            f"/v1/default/banks/{quote(bank_id, safe='')}/memories/{quote(memory_id, safe='')}",
            {"state": "invalidated", "reason": reason},
        )

    async def _request(
        self,
        operation: str,
        method: str,
        path: str,
        body: Any = None,
        *,
        preserve_http_status: bool = False,
    ) -> Any:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        request_id = current_request_id()
        if request_id:
            headers["x-request-id"] = request_id
        request = self.client.build_request(
            method,
            self.base_url + path,
            headers=headers,
            json=body if body is not None else None,
        )
        response: httpx.Response | None = None
        try:
            async with asyncio.timeout(self.timeout_ms / 1000.0):
                response = await self.client.send(request, stream=True)
                if not response.is_success:
                    client_status = None
                    if (
                        preserve_http_status
                        and 400 <= response.status_code < 500
                        and response.status_code not in {401, 403}
                    ):
                        client_status = response.status_code
                    raise HindsightGatewayError(
                        "http",
                        upstream_status=response.status_code,
                        operation=operation,
                        method=method,
                        client_status=client_status,
                    )
                content_length = response.headers.get("content-length")
                if (
                    content_length
                    and content_length.isdigit()
                    and int(content_length) > self.max_response_bytes
                ):
                    raise HindsightGatewayError(
                        "response-too-large",
                        upstream_status=response.status_code,
                        operation=operation,
                        method=method,
                    )
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise HindsightGatewayError(
                            "response-too-large",
                            upstream_status=response.status_code,
                            operation=operation,
                            method=method,
                        )
                    chunks.append(chunk)
                raw = b"".join(chunks)
                if not raw:
                    # Callers validate whether an empty success is legal. Facade
                    # routes pin their own client status and serialize it as JSON null.
                    return None
                try:
                    value = json.loads(raw, parse_constant=_reject_non_finite)
                    _assert_response_depth(value)
                    _assert_finite_numbers(value)
                    return value
                except (ValueError, UnicodeError, RecursionError) as exc:
                    raise HindsightGatewayError(
                        "invalid-response",
                        upstream_status=response.status_code,
                        operation=operation,
                        method=method,
                    ) from exc
        except (TimeoutError, httpx.TimeoutException) as exc:
            raise HindsightGatewayError(
                "timeout", operation=operation, method=method, timeout_ms=self.timeout_ms
            ) from exc
        except HindsightGatewayError:
            raise
        except httpx.HTTPError as exc:
            raise HindsightGatewayError("network", operation=operation, method=method) from exc
        finally:
            if response is not None:
                await response.aclose()
