from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx
from pydantic import ValidationError

from .errors import HttpError
from .models import RecallBody, RecallResponse, RetainBody


class HindsightGatewayError(HttpError):
    def __init__(
        self,
        kind: str,
        *,
        operation: str,
        method: str,
        upstream_status: int | None = None,
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
        self.operation = operation
        self.method = method
        self.upstream_status = upstream_status
        self.timeout_ms = timeout_ms

    def details(self) -> dict[str, Any]:
        return {
            "error_kind": self.kind,
            "status": self.status,
            **({"upstream_status": self.upstream_status} if self.upstream_status is not None else {}),
            "operation": self.operation,
            "method": self.method,
            **({"timeout_ms": self.timeout_ms} if self.timeout_ms is not None else {}),
        }


def gateway_error_kind(error: BaseException) -> str:
    return error.kind if isinstance(error, HindsightGatewayError) else "unknown"


class HindsightGateway:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout_ms: int = 10_000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if timeout_ms <= 0:
            raise ValueError("Hindsight timeout must be a positive integer")
        self.base_url = base_url.rstrip("/")
        self.timeout_ms = timeout_ms
        headers = {"content-type": "application/json"}
        if api_key:
            headers["authorization"] = f"Bearer {api_key}"
        timeout = httpx.Timeout(timeout_ms / 1000.0)
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout, transport=transport)

    async def close(self) -> None:
        await self._client.aclose()

    async def health(self) -> Any:
        return await self._json("GET", "/health", "health")

    async def version(self) -> Any:
        return await self._json("GET", "/version", "version")

    async def retain(self, bank_id: str, body: RetainBody | dict[str, Any]) -> Any:
        payload = body.model_dump_wire() if isinstance(body, RetainBody) else body
        return await self._json(
            "POST",
            f"/v1/default/banks/{quote(bank_id, safe='')}/memories",
            "retain",
            payload,
        )

    async def recall(self, bank_id: str, body: RecallBody | dict[str, Any]) -> RecallResponse:
        payload = body.model_dump(exclude_none=True) if isinstance(body, RecallBody) else body
        value = await self._json(
            "POST",
            f"/v1/default/banks/{quote(bank_id, safe='')}/memories/recall",
            "recall",
            payload,
        )
        try:
            return RecallResponse.model_validate(value)
        except ValidationError as exc:
            raise HindsightGatewayError(
                "invalid-response", operation="recall", method="POST"
            ) from exc

    async def invalidate_memory(self, bank_id: str, memory_id: str, reason: str) -> None:
        await self._json(
            "PATCH",
            f"/v1/default/banks/{quote(bank_id, safe='')}/memories/{quote(memory_id, safe='')}",
            "invalidate_memory",
            {"state": "invalidated", "reason": reason},
        )

    async def _json(
        self, method: str, path: str, operation: str, body: Any | None = None
    ) -> Any:
        request = self._client.build_request(
            method, f"{self.base_url}{path}", json=body if body is not None else None
        )
        response: httpx.Response | None = None
        try:
            response = await self._client.send(request, stream=True)
            raw = await response.aread()
        except httpx.TimeoutException as exc:
            if response is not None:
                await response.aclose()
            raise HindsightGatewayError(
                "timeout",
                operation=operation,
                method=method,
                timeout_ms=self.timeout_ms,
            ) from exc
        except httpx.HTTPError as exc:
            if response is not None:
                await response.aclose()
            raise HindsightGatewayError(
                "network", operation=operation, method=method
            ) from exc

        try:
            if response.status_code < 200 or response.status_code >= 300:
                raise HindsightGatewayError(
                    "http",
                    operation=operation,
                    method=method,
                    upstream_status=response.status_code,
                )
            if not raw:
                return None
            try:
                return response.json()
            except ValueError as exc:
                raise HindsightGatewayError(
                    "invalid-response",
                    operation=operation,
                    method=method,
                    upstream_status=response.status_code,
                ) from exc
        finally:
            await response.aclose()
