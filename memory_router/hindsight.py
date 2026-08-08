from __future__ import annotations

from typing import Any, Literal, cast
from urllib.parse import quote

import httpx
from pydantic import ValidationError

from .errors import HttpError
from .models import RecallResponse

DEFAULT_HINDSIGHT_TIMEOUT_MS = 10_000


class HindsightGatewayError(HttpError):
    def __init__(
        self,
        kind: Literal["timeout", "http", "invalid-response", "network"],
        *,
        upstream_status: int | None = None,
        operation: str | None = None,
        method: str | None = None,
        timeout_ms: int | None = None,
    ) -> None:
        code = {
            "timeout": "hindsight_timeout",
            "http": "hindsight_http_error",
            "invalid-response": "hindsight_invalid_response",
            "network": "hindsight_unavailable",
        }[kind]
        message = {
            "timeout": "Upstream memory service timed out",
            "http": "Upstream memory service request failed",
            "invalid-response": "Upstream memory service returned an invalid response",
            "network": "Upstream memory service is unavailable",
        }[kind]
        super().__init__(504 if kind == "timeout" else 502, code, message)
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


class HindsightGateway:
    def __init__(
        self, base_url: str, api_key: str | None, timeout_ms: int = DEFAULT_HINDSIGHT_TIMEOUT_MS
    ) -> None:
        if timeout_ms <= 0:
            raise RuntimeError("Hindsight timeout must be a positive integer")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_ms = timeout_ms
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(timeout_ms / 1000.0))

    async def close(self) -> None:
        await self.client.aclose()

    async def health(self) -> Any:
        return await self._request("health", "GET", "/health")

    async def version(self) -> Any:
        return await self._request("version", "GET", "/version")

    async def retain(self, bank_id: str, body: dict[str, Any]) -> Any:
        return await self._request(
            "retain", "POST", f"/v1/default/banks/{quote(bank_id, safe='')}/memories", body
        )

    async def recall(self, bank_id: str, body: dict[str, Any]) -> dict[str, Any]:
        value = await self._request(
            "recall", "POST", f"/v1/default/banks/{quote(bank_id, safe='')}/memories/recall", body
        )
        try:
            RecallResponse.model_validate(value)
        except ValidationError as exc:
            raise HindsightGatewayError(
                "invalid-response", operation="recall", method="POST"
            ) from exc
        return cast(dict[str, Any], value)

    async def invalidate_memory(self, bank_id: str, memory_id: str, reason: str) -> None:
        await self._request(
            "invalidate_memory",
            "PATCH",
            f"/v1/default/banks/{quote(bank_id, safe='')}/memories/{quote(memory_id, safe='')}",
            {"state": "invalidated", "reason": reason},
        )

    async def _request(self, operation: str, method: str, path: str, body: Any = None) -> Any:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        try:
            response = await self.client.request(
                method,
                self.base_url + path,
                headers=headers,
                json=body if body is not None else None,
            )
        except httpx.TimeoutException as exc:
            raise HindsightGatewayError(
                "timeout", operation=operation, method=method, timeout_ms=self.timeout_ms
            ) from exc
        except httpx.HTTPError as exc:
            raise HindsightGatewayError("network", operation=operation, method=method) from exc
        if not response.is_success:
            await response.aclose()
            raise HindsightGatewayError(
                "http", upstream_status=response.status_code, operation=operation, method=method
            )
        try:
            if not response.content:
                return None
            return response.json()
        except (ValueError, UnicodeError) as exc:
            raise HindsightGatewayError(
                "invalid-response",
                upstream_status=response.status_code,
                operation=operation,
                method=method,
            ) from exc
