from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from .errors import HttpError
from .facade_routes import match_facade_route
from .hindsight import HindsightGateway
from .openclaw import OpenClawFacade
from .policy import RouterPolicy
from .principal_gate import log_authorization_decision, require_grant
from .principals import (
    SCOPE_BANK_ADMIN,
    SCOPE_BANK_LIST,
    SCOPE_MEMORY_RECALL,
    SCOPE_MEMORY_RETAIN,
    PrincipalResolver,
    PrincipalSession,
    facade_scope,
    scope_limit_operation,
)
from .validation import parse_recall_body, parse_reflect_body, parse_retain_body

EMPTY_BODY = object()


class JsonBodyReader(Protocol):
    async def __call__(
        self,
        request: Request,
        *,
        empty_as_none: bool = False,
        max_bytes: int | None = None,
    ) -> Any: ...


class ConcurrencyRunner(Protocol):
    async def __call__(
        self,
        request: Request,
        session: PrincipalSession,
        scope: str,
        operation: Callable[[], Awaitable[Any]],
    ) -> Any: ...


PrincipalRate = Callable[[PrincipalSession, str, str], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class DispatchDependencies:
    policy: RouterPolicy
    resolver: PrincipalResolver | None
    hindsight: HindsightGateway | None
    json_body: JsonBodyReader
    principal_rate: PrincipalRate
    concurrency: ConcurrencyRunner
    decode_path_segment: Callable[[str], str]
    facade_factory: Callable[[RouterPolicy], OpenClawFacade]


class AuthenticatedRequestDispatcher:
    def __init__(self, dependencies: DispatchDependencies) -> None:
        self.policy = dependencies.policy
        self.resolver = dependencies.resolver
        self.hindsight = dependencies.hindsight
        self.json_body = dependencies.json_body
        self.principal_rate = dependencies.principal_rate
        self.concurrency = dependencies.concurrency
        self.decode_path_segment = dependencies.decode_path_segment
        self.facade_factory = dependencies.facade_factory

    async def dispatch(
        self,
        request: Request,
        pathname: str,
        method: str,
        principal: PrincipalSession | None,
        route_class: str,
    ) -> Response:
        response = await self._dispatch_bank_list(request, pathname, method, principal, route_class)
        if response is not None:
            return response
        response = await self._dispatch_memory(request, pathname, method, principal, route_class)
        if response is not None:
            return response
        response = await self._dispatch_facade(request, pathname, method, principal, route_class)
        if response is not None:
            return response
        return await self._dispatch_denied(pathname, method, principal, route_class)

    async def _dispatch_bank_list(
        self,
        request: Request,
        pathname: str,
        method: str,
        principal: PrincipalSession | None,
        route_class: str,
    ) -> Response | None:
        if principal is not None and method == "GET" and pathname == "/v1/default/banks":
            resolver = _require(self.resolver, "principal resolver")
            await self.principal_rate(principal, SCOPE_BANK_LIST, route_class)
            banks = resolver.list_banks(principal)
            if not banks:
                log_authorization_decision(
                    route_class=route_class,
                    session=principal,
                    bank="-",
                    scope=SCOPE_BANK_LIST,
                    allowed=False,
                    latency_ms=0.0,
                )
                raise HttpError(403, "authorization_denied", "principal lacks the required grant")
            for bank in banks:
                log_authorization_decision(
                    route_class=route_class,
                    session=principal,
                    bank=bank,
                    scope=SCOPE_BANK_LIST,
                    allowed=True,
                    latency_ms=0.0,
                )
            q, limit, offset = _bank_list_query(request)
            hindsight = _require(self.hindsight, "hindsight gateway")
            payload = await self.concurrency(
                request,
                principal,
                SCOPE_BANK_LIST,
                lambda: hindsight.list_banks(banks, q=q, limit=limit, offset=offset),
            )
            return JSONResponse(payload)
        return None

    async def _dispatch_memory(
        self,
        request: Request,
        pathname: str,
        method: str,
        principal: PrincipalSession | None,
        route_class: str,
    ) -> Response | None:
        match = re.fullmatch(r"/v1/default/banks/([^/]+)/memories(?:/(recall))?", pathname)
        if method == "POST" and match:
            writer_id, action = self.decode_path_segment(match.group(1)), match.group(2)
            if principal is None:
                return await self._dispatch_legacy_memory(request, writer_id, action)
            scope = SCOPE_MEMORY_RECALL if action == "recall" else SCOPE_MEMORY_RETAIN
            await self.principal_rate(principal, scope, route_class)
            require_grant(session=principal, scope=scope, bank=writer_id, route_class=route_class)
            body_limit = principal.limits[scope_limit_operation(scope)].max_body_bytes
            if action == "recall":
                body = parse_recall_body(await self.json_body(request, max_bytes=body_limit))
                self.policy.limits.assert_recall_bounds(body)
                payload = await self.concurrency(
                    request,
                    principal,
                    scope,
                    lambda: self.policy.recall_bank(principal.principal_id, writer_id, body),
                )
            else:
                body = parse_retain_body(await self.json_body(request, max_bytes=body_limit))
                self.policy.limits.assert_retain_bounds(body)
                payload = await self.concurrency(
                    request,
                    principal,
                    scope,
                    lambda: self.policy.retain_bank(principal.principal_id, writer_id, body),
                )
            return JSONResponse(payload)
        return None

    async def _dispatch_legacy_memory(
        self, request: Request, writer_id: str, action: str | None
    ) -> Response:
        if action == "recall":
            body = parse_recall_body(await self.json_body(request))
            self.policy.limits.assert_recall_bounds(body)
            return JSONResponse(await self.policy.recall(writer_id, body))
        body = parse_retain_body(await self.json_body(request))
        self.policy.limits.assert_retain_bounds(body)
        return JSONResponse(await self.policy.retain(writer_id, body))

    async def _dispatch_facade(
        self,
        request: Request,
        pathname: str,
        method: str,
        principal: PrincipalSession | None,
        route_class: str,
    ) -> Response | None:
        matched = self._match_facade(method, pathname)
        if matched is None:
            return None
        route, route_match = matched
        bank = route_match.group("bank")
        scope = facade_scope(route)
        if principal is not None:
            await self.principal_rate(principal, scope, route_class)
            require_grant(session=principal, scope=scope, bank=bank, route_class=route_class)
        body = await self._facade_body(request, route.body, route.body_label, principal, scope)
        if route.template == "reflect" and body is not None:
            body = parse_reflect_body(body)
        facade = self.facade_factory(self.policy)

        def operation() -> Awaitable[dict[str, Any]]:
            return facade.forward(
                route=route,
                writer_id=principal.principal_id if principal is not None else bank,
                params={name: route_match.group(name) for name in route.params},
                body=body,
                query=list(request.query_params.multi_items()) or None,
                bank_override=bank if principal is not None else None,
            )

        payload = (
            await self.concurrency(request, principal, scope, operation)
            if principal is not None
            else await operation()
        )
        return JSONResponse(payload, status_code=route.success_status)

    def _match_facade(self, method: str, pathname: str) -> Any:
        if not pathname.startswith("/v1/default/banks/"):
            return match_facade_route(method, pathname)
        try:
            decoded = "/".join(self.decode_path_segment(part) for part in pathname.split("/"))
        except HttpError as exc:
            if exc.code == "invalid_path_segment":
                raise
            matched = match_facade_route(method, pathname)
            if matched is not None:
                raise
            return None
        return match_facade_route(method, decoded)

    async def _facade_body(
        self,
        request: Request,
        requirement: str,
        label: str,
        principal: PrincipalSession | None,
        scope: str,
    ) -> dict[str, Any] | None:
        if requirement == "none":
            return None
        max_bytes = (
            principal.limits[scope_limit_operation(scope)].max_body_bytes
            if principal is not None
            else None
        )
        raw = await self.json_body(request, empty_as_none=True, max_bytes=max_bytes)
        if raw is EMPTY_BODY:
            if requirement == "required":
                raise HttpError(400, "invalid_request", f"{label} body is required")
            return None
        if raw is None:
            if requirement != "optional":
                raise HttpError(400, "invalid_request", f"{label} body must be an object")
            return None
        if not isinstance(raw, dict):
            raise HttpError(400, "invalid_request", f"{label} body must be an object")
        return raw

    async def _dispatch_denied(
        self,
        pathname: str,
        method: str,
        principal: PrincipalSession | None,
        route_class: str,
    ) -> Response:
        denied_writer_id = self._known_denied_bank(pathname)
        if principal is not None:
            await self.principal_rate(principal, SCOPE_BANK_ADMIN, route_class)
            denied = await self.policy.deny_endpoint(
                method, pathname, writer_id=principal.principal_id
            )
        else:
            denied = (
                await self.policy.deny_endpoint(method, pathname)
                if denied_writer_id is None
                else await self.policy.deny_endpoint(method, pathname, writer_id=denied_writer_id)
            )
        return JSONResponse(denied, status_code=404)

    def _known_denied_bank(self, pathname: str) -> str | None:
        match = re.match(r"/v1/default/banks/([^/]+)(?:/|$)", pathname)
        if match is None:
            return None
        try:
            candidate = self.decode_path_segment(match.group(1))
        except HttpError:
            return None
        writers = getattr(getattr(self.policy, "registry", None), "writers", {})
        return candidate if candidate in writers else None


def _bank_list_query(request: Request) -> tuple[str | None, int, int]:
    pairs = list(request.query_params.multi_items())
    if any(key not in {"q", "limit", "offset"} for key, _ in pairs):
        raise HttpError(400, "invalid_query", "unsupported bank-list query parameter")
    if any(sum(1 for key, _ in pairs if key == name) > 1 for name in {"q", "limit", "offset"}):
        raise HttpError(400, "invalid_query", "duplicate bank-list query parameter")
    q = request.query_params.get("q")
    try:
        limit = int(request.query_params.get("limit", "100"), 10)
        offset = int(request.query_params.get("offset", "0"), 10)
    except ValueError as exc:
        raise HttpError(400, "invalid_query", "invalid integer query parameter") from exc
    if not 0 <= limit <= 500 or offset < 0:
        raise HttpError(400, "invalid_query", "integer query parameter out of range")
    return q, limit, offset


def _require[T](value: T | None, component: str) -> T:
    if value is None:
        raise RuntimeError(f"memory-router runtime {component} is not initialized")
    return value
