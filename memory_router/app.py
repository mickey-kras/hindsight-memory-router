from __future__ import annotations

import asyncio
import json
import re
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote_to_bytes

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .auth import AuthFailureAuditor, is_admin_authorized, is_router_authorized
from .config import Settings, is_postgres_url, warn_auth
from .errors import HttpError, safe_error_body
from .hindsight import HindsightGateway, HindsightGatewayError
from .policy import MemoryRouterPolicy
from .quarantine.admin import QuarantineAdminService
from .quarantine.db import create_database, validate_sqlite_storage
from .quarantine.repository import QuarantineRepository
from .quarantine.store import EncryptedDatabaseQuarantineStore
from .rate_limits import (
    HindsightLimits,
    InMemorySlidingWindowRateLimiter,
    PostgresSlidingWindowRateLimiter,
    Rule,
)
from .registry import load_registry
from .validation import parse_recall_body, parse_retain_body

_MEMORY_RETAIN = re.compile(r"^/v1/default/banks/([^/]+)/memories$")
_MEMORY_RECALL = re.compile(r"^/v1/default/banks/([^/]+)/memories/recall$")
_ADMIN_ITEM = re.compile(
    r"^/admin/quarantine/items/([^/]+)(?:/(approve|reject|postpone))?$"
)


@dataclass(slots=True)
class Runtime:
    settings: Settings
    repository: QuarantineRepository
    rate_limiter: Any
    hindsight: Any
    policy: MemoryRouterPolicy
    admin: QuarantineAdminService
    audit_auth_failure: AuthFailureAuditor
    admin_rate_limiter: "AdminRateLimiter"
    sweeper_task: asyncio.Task[None] | None = None

    async def close(self) -> None:
        if self.sweeper_task is not None:
            self.sweeper_task.cancel()
            try:
                await self.sweeper_task
            except asyncio.CancelledError:
                pass
        await self.hindsight.close()
        await self.rate_limiter.close()
        await self.repository.close()


class AdminRateLimiter:
    def __init__(self, settings: Settings) -> None:
        self._limiter = InMemorySlidingWindowRateLimiter()
        self.read_max = settings.admin_rate_read_max
        self.write_max = settings.admin_rate_write_max
        self.window_ms = settings.admin_rate_window_ms

    async def consume(self, request_class: str) -> None:
        maximum = self.read_max if request_class == "read" else self.write_max
        try:
            await self._limiter.consume(
                f"admin:{request_class}", Rule(maximum, self.window_ms)
            )
        except HttpError as exc:
            if exc.status == 429:
                raise HttpError(
                    429,
                    "admin_rate_limited",
                    f"too many admin {request_class} requests",
                ) from exc
            raise


async def build_runtime(settings: Settings | None = None) -> Runtime:
    settings = settings or Settings.from_env()
    warn_auth(settings)
    registry = load_registry(settings.registry_path)
    database = create_database(settings.quarantine_database_url)
    repository = QuarantineRepository(database)
    await repository.initialize()
    await repository.ping()
    validate_sqlite_storage(settings.quarantine_database_url)

    rate_limiter: Any
    if is_postgres_url(settings.quarantine_database_url):
        rate_limiter = PostgresSlidingWindowRateLimiter(settings.quarantine_database_url)
    else:
        rate_limiter = InMemorySlidingWindowRateLimiter()
    await rate_limiter.initialize()

    hindsight = HindsightGateway(
        settings.hindsight_base_url,
        settings.hindsight_api_key,
        settings.hindsight_timeout_ms,
    )
    limits = HindsightLimits(settings.hindsight_limits, rate_limiter)
    store = EncryptedDatabaseQuarantineStore(
        settings.quarantine_public_key,
        repository,
        settings.quarantine_limits,
        rate_limiter,
    )
    policy = MemoryRouterPolicy(registry, hindsight, store, repository, limits)
    admin = QuarantineAdminService(
        repository, hindsight, registry, settings.max_postpones
    )
    runtime = Runtime(
        settings=settings,
        repository=repository,
        rate_limiter=rate_limiter,
        hindsight=hindsight,
        policy=policy,
        admin=admin,
        audit_auth_failure=AuthFailureAuditor(store),
        admin_rate_limiter=AdminRateLimiter(settings),
    )
    if settings.sweep_interval_seconds > 0:
        runtime.sweeper_task = asyncio.create_task(_sweeper(runtime))
    return runtime


def create_app(runtime: Runtime | None = None) -> FastAPI:
    holder: dict[str, Runtime] = {}

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if runtime is not None:
            holder["runtime"] = runtime
            yield
            return
        built = await build_runtime()
        holder["runtime"] = built
        try:
            yield
        finally:
            await built.close()

    app = FastAPI(
        title="Memory Router",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.api_route(
        "/{path:path}",
        methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    @app.api_route(
        "/",
        methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    async def dispatch(request: Request, path: str = "") -> JSONResponse:
        rt = holder["runtime"]
        try:
            pathname = _raw_path(request)
            method = request.method.upper()

            if method == "GET" and pathname == "/health":
                return _send(200, {"status": "healthy", "service": "memory-router"})
            if method == "GET" and pathname == "/ready":
                try:
                    await rt.repository.ping()
                    return _send(
                        200, {"status": "ready", "service": "memory-router"}
                    )
                except BaseException:
                    return _send(
                        503, {"status": "not_ready", "service": "memory-router"}
                    )

            if pathname.startswith("/admin/"):
                scope = _admin_scope(method, pathname)
                if not is_admin_authorized(
                    request.headers.get("authorization"),
                    scope,
                    legacy=rt.settings.admin_legacy_token,
                    read=rt.settings.admin_read_token,
                    review=rt.settings.admin_review_token,
                    cleanup=rt.settings.admin_cleanup_token,
                ):
                    await rt.audit_auth_failure("admin")
                    return _send(401, {"error": "unauthorized"})
                await rt.admin_rate_limiter.consume(
                    "read" if method in {"GET", "HEAD"} else "write"
                )
                if method == "GET" and pathname == "/admin/quarantine/queue":
                    limit = _integer_query(request, "limit", 100, 1, 500)
                    offset = _integer_query(request, "offset", 0, 0, 2**31 - 1)
                    return _send(
                        200, await rt.admin.list_queue(limit=limit, offset=offset)
                    )
                if method == "GET" and pathname == "/admin/quarantine/stats":
                    return _send(200, await rt.admin.stats())
                if method == "POST" and pathname == "/admin/quarantine/cleanup":
                    body = await _read_json(request, rt.settings.max_body_bytes)
                    if not isinstance(body, dict):
                        raise HttpError(
                            400, "invalid_request", "cleanup body must be an object"
                        )
                    return _send(200, await rt.admin.cleanup(body))
                item = _parse_admin_item(pathname)
                if item is not None:
                    qid, action = item
                    if action == "read" and method == "GET":
                        return _send(200, await rt.admin.read_item(qid))
                    if action == "approve" and method == "POST":
                        body = await _read_json(request, rt.settings.max_body_bytes)
                        if not isinstance(body, dict):
                            raise HttpError(
                                400,
                                "invalid_request",
                                "review body must be an object",
                            )
                        return _send(200, await rt.admin.approve(qid, body))
                    if action == "reject" and method == "POST":
                        return _send(200, await rt.admin.reject(qid))
                    if action == "postpone" and method == "POST":
                        return _send(200, await rt.admin.postpone(qid))
                return _send(404, {"error": "admin_endpoint_not_found"})

            if not is_router_authorized(
                request.headers.get("authorization"),
                rt.settings.router_token,
                rt.settings.allow_anonymous,
            ):
                await rt.audit_auth_failure("router")
                return _send(401, {"error": "unauthorized"})

            if method == "GET" and pathname == "/version":
                return _send(
                    200,
                    {
                        "api_version": "0.9.0",
                        "router": "memory-router",
                        "features": {
                            "policy_facade": True,
                            "encrypted_quarantine": True,
                            "quarantine_admin_api": True,
                            "quarantine_database": True,
                        },
                    },
                )

            memory = _parse_memory_path(pathname)
            if method == "POST" and memory and memory[1] == "retain":
                body = parse_retain_body(
                    await _read_json(request, rt.settings.max_body_bytes)
                )
                rt.policy.limits.assert_retain_bounds(body)
                return _send(200, await rt.policy.retain(memory[0], body))
            if method == "POST" and memory and memory[1] == "recall":
                body = parse_recall_body(
                    await _read_json(request, rt.settings.max_body_bytes)
                )
                rt.policy.limits.assert_recall_bounds(body)
                return _send(200, await rt.policy.recall(memory[0], body))

            denied = await rt.policy.deny_endpoint(method, pathname)
            return _send(404, denied)
        except BaseException as exc:
            if isinstance(exc, HindsightGatewayError):
                details = {
                    "kind": exc.kind,
                    "operation": exc.operation,
                    "method": exc.method,
                    **(
                        {"upstream_status": exc.upstream_status}
                        if exc.upstream_status is not None
                        else {}
                    ),
                }
                sys.stderr.write(
                    f"memory-router upstream request failed: {json.dumps(details, separators=(',', ':'))}\n"
                )
            status, body, headers = safe_error_body(exc)
            return _send(status, body, headers)

    return app


def _raw_path(request: Request) -> str:
    raw = request.scope.get("raw_path")
    if isinstance(raw, bytes):
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise HttpError(400, "invalid_url", "request URL is malformed") from exc
    path = request.scope.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        raise HttpError(400, "invalid_url", "request URL is malformed")
    return path


async def _read_json(request: Request, max_body_bytes: int) -> Any:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_body_bytes:
            raise HttpError(413, "payload_too_large", "payload too large")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HttpError(400, "invalid_json", "invalid JSON body") from exc


def _decode_segment(segment: str) -> str:
    if re.search(r"%(?![0-9A-Fa-f]{2})", segment):
        raise HttpError(
            400,
            "invalid_path_encoding",
            "path segment contains malformed percent-encoding",
        )
    try:
        return unquote_to_bytes(segment).decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise HttpError(
            400,
            "invalid_path_encoding",
            "path segment contains malformed percent-encoding",
        ) from exc


def _parse_memory_path(path: str) -> tuple[str, str] | None:
    match = _MEMORY_RETAIN.fullmatch(path)
    if match:
        return _decode_segment(match.group(1)), "retain"
    match = _MEMORY_RECALL.fullmatch(path)
    if match:
        return _decode_segment(match.group(1)), "recall"
    return None


def _parse_admin_item(path: str) -> tuple[str, str] | None:
    match = _ADMIN_ITEM.fullmatch(path)
    if not match:
        return None
    return _decode_segment(match.group(1)), match.group(2) or "read"


def _integer_query(
    request: Request, name: str, fallback: int, minimum: int, maximum: int
) -> int:
    values = request.query_params.getlist(name)
    if not values:
        return fallback
    if len(values) > 1:
        raise HttpError(400, "invalid_query", f"{name} is invalid")
    raw = values[0]
    try:
        text = raw.strip()
        number = 0.0 if text == "" else float(text)
    except ValueError as exc:
        raise HttpError(400, "invalid_query", f"{name} is invalid") from exc
    if (
        not number.is_integer()
        or not (-9_007_199_254_740_991 <= number <= 9_007_199_254_740_991)
        or number < minimum
        or number > maximum
    ):
        raise HttpError(400, "invalid_query", f"{name} is invalid")
    return int(number)


def _admin_scope(method: str, path: str) -> str:
    if method == "POST" and path == "/admin/quarantine/cleanup":
        return "cleanup"
    if method in {"GET", "HEAD"}:
        return "read"
    return "review"


def _send(
    status: int, body: Any, headers: dict[str, str] | Any = None
) -> JSONResponse:
    return JSONResponse(
        content=body,
        status_code=status,
        headers={"content-type": "application/json", **dict(headers or {})},
    )


async def _sweeper(runtime: Runtime) -> None:
    interval = runtime.settings.sweep_interval_seconds
    while True:
        await asyncio.sleep(interval)
        now = datetime.now(timezone.utc)
        at = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        try:
            while (
                await runtime.repository.sweep_expired_items(at)
                >= 1000
            ):
                pass
            if runtime.settings.event_retention_days > 0:
                cutoff = (
                    now - timedelta(days=runtime.settings.event_retention_days)
                ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                while (
                    await runtime.repository.prune_events_before(cutoff, at)
                    >= 1000
                ):
                    pass
        except BaseException as exc:
            if isinstance(exc, asyncio.CancelledError):
                raise
            sys.stderr.write(
                "memory-router quarantine retention sweep failed: "
                f"{type(exc).__name__}\n"
            )
