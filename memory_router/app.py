from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from importlib.metadata import PackageNotFoundError, version as package_version
from typing import Any
from urllib.parse import unquote

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .admin import QuarantineAdminService
from .auth import AuthFailureAuditor, admin_authorized, admin_token_recognized, router_authorized
from .config import (
    assert_auth_environment,
    assert_deployment_mode,
    assert_no_private_key_environment,
    boolean_env,
    integer_env,
    load_registry,
)
from .db import (
    DEFAULT_DATABASE_URL,
    PostgresDatabase,
    create_database,
    is_postgres,
    validate_storage,
)
from .errors import HttpError
from .hindsight import HindsightGateway, HindsightGatewayError
from .limits import HindsightLimitConfig, HindsightLimits
from .maintenance import prune_events_before, sweep_expired
from .observability import current_request_id
from .policy import RouterPolicy
from .quarantine_store import QuarantineLimits, QuarantineStore
from .rate_limit import InMemoryRateLimiter, PostgresRateLimiter
from .repository import QuarantineRepository
from .review_repository import recover_interrupted
from .timestamps import iso_now
from .validation import parse_recall_body, parse_retain_body

logger = logging.getLogger(__name__)
_PERCENT_DOT = re.compile(r"%2e", re.I)
_INVALID_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MAX_JSON_DEPTH = 64
_PROCESS_START = time.monotonic()
try:
    _ROUTER_VERSION = package_version("hindsight-memory-router")
except PackageNotFoundError:
    _ROUTER_VERSION = "0.0.0"


def _now() -> str:
    return iso_now()


def _scope(method: str, path: str) -> str:
    if method == "GET":
        return "read"
    if method == "POST" and path == "/admin/quarantine/cleanup":
        return "cleanup"
    return "review"


def _require_runtime[T](value: T | None, component: str) -> T:
    if value is None:
        raise RuntimeError(f"memory-router runtime {component} is not initialized")
    return value


def _raw_pathname(request: Request) -> str:
    raw = request.scope.get("raw_path")
    path = raw.decode("latin-1") if isinstance(raw, bytes) else request.url.path
    return _normalize_dot_segments(path)


def _normalize_dot_segments(path: str) -> str:
    segments = path.split("/")
    output: list[str] = []
    last_index = len(segments) - 1
    for index, segment in enumerate(segments):
        dot_segment = _PERCENT_DOT.sub(".", segment)
        if dot_segment == ".":
            if index == last_index:
                output.append("")
            continue
        if dot_segment == "..":
            if output and not (len(output) == 1 and output[0] == ""):
                output.pop()
            if index == last_index:
                output.append("")
            continue
        output.append(segment)
    return "/".join(output)


def _decode_path_segment(value: str) -> str:
    if _INVALID_PERCENT.search(value):
        raise HttpError(
            400, "invalid_path_encoding", "path segment contains malformed percent-encoding"
        )
    try:
        return unquote(value, encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise HttpError(
            400, "invalid_path_encoding", "path segment contains malformed percent-encoding"
        ) from exc


def _assert_json_depth(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_JSON_DEPTH:
            raise HttpError(400, "json_too_deep", "JSON nesting depth exceeds limit")
        if isinstance(current, dict):
            stack.extend((entry, depth + 1) for entry in current.values())
        elif isinstance(current, list):
            stack.extend((entry, depth + 1) for entry in current)


class Runtime:
    def __init__(self) -> None:
        self.database: Any = None
        self.rate_limit_database: PostgresDatabase | None = None
        self.repository: QuarantineRepository | None = None
        self.hindsight: HindsightGateway | None = None
        self.policy: RouterPolicy | None = None
        self.admin: QuarantineAdminService | None = None
        self.auditor: AuthFailureAuditor | None = None
        self.quarantine_limiter: Any = None
        self.admin_limiter = InMemoryRateLimiter()
        self.auth_limiter: Any = InMemoryRateLimiter()
        self.sweeper: asyncio.Task[None] | None = None
        self.max_body_bytes = integer_env("MEMORY_ROUTER_MAX_BODY_BYTES", 1_048_576, minimum=1)
        self.router_token = os.environ.get("MEMORY_ROUTER_TOKEN")
        self.allow_anonymous = boolean_env("MEMORY_ROUTER_ALLOW_ANONYMOUS", False)
        self.admin_tokens = {
            "legacy": os.environ.get("MEMORY_ROUTER_ADMIN_TOKEN"),
            "read": os.environ.get("MEMORY_ROUTER_ADMIN_READ_TOKEN"),
            "review": os.environ.get("MEMORY_ROUTER_ADMIN_REVIEW_TOKEN"),
            "cleanup": os.environ.get("MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN"),
        }
        self.admin_read_max = integer_env("MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX", 120, minimum=1)
        self.admin_write_max = integer_env(
            "MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX", 30, minimum=1
        )
        self.admin_window = integer_env(
            "MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS", 60_000, minimum=1
        )
        self.auth_failure_max = integer_env(
            "MEMORY_ROUTER_AUTH_FAILURE_RATE_LIMIT_MAX", 120, minimum=1
        )
        self.auth_failure_window = integer_env(
            "MEMORY_ROUTER_AUTH_FAILURE_RATE_LIMIT_WINDOW_MS", 60_000, minimum=1
        )
        self.review_stale_seconds = 60

    async def start(self) -> None:
        assert_no_private_key_environment()
        assert_auth_environment()
        hindsight_timeout_ms = integer_env("HINDSIGHT_TIMEOUT_MS", 10_000, minimum=1)
        self.review_stale_seconds = max(60, (hindsight_timeout_ms + 999) // 1000 + 30)
        database_url = os.environ.get("QUARANTINE_DATABASE_URL", DEFAULT_DATABASE_URL)
        assert_deployment_mode(database_url)
        self.database = await create_database(database_url)
        self.repository = QuarantineRepository(self.database)
        await validate_storage(self.database, database_url)
        await recover_interrupted(self.repository, _now(), self.review_stale_seconds)
        if is_postgres(database_url):
            self.rate_limit_database = PostgresDatabase(database_url, max_size=2)
            await self.rate_limit_database.initialize()
            self.quarantine_limiter = PostgresRateLimiter(self.rate_limit_database)
            await self.quarantine_limiter.initialize()
            self.auth_limiter = self.quarantine_limiter
        else:
            self.quarantine_limiter = InMemoryRateLimiter()
            self.auth_limiter = InMemoryRateLimiter()
        public_key = os.environ.get("QUARANTINE_PUBLIC_KEY", "")
        limits = QuarantineLimits(
            max_item_bytes=integer_env("QUARANTINE_MAX_ITEM_BYTES", 1_048_576),
            max_pending_items=integer_env("QUARANTINE_MAX_PENDING_ITEMS", 1_000),
            max_pending_items_per_writer=integer_env("QUARANTINE_MAX_PENDING_ITEMS_PER_WRITER", 50),
            max_encrypted_bytes=integer_env("QUARANTINE_MAX_ENCRYPTED_BYTES", 104_857_600),
            rate_limit_max=integer_env("QUARANTINE_RATE_LIMIT_MAX", 30),
            rate_limit_window_ms=integer_env("QUARANTINE_RATE_LIMIT_WINDOW_MS", 60_000),
            rate_limit_global_max=integer_env("QUARANTINE_RATE_LIMIT_GLOBAL_MAX", 300),
            distinct_family_limit_max=integer_env("QUARANTINE_DISTINCT_FAMILY_LIMIT_MAX", 10),
            requarantine_ops_max=integer_env("QUARANTINE_REQUARANTINE_OPS_MAX", 1_000),
            item_ttl_days=integer_env("QUARANTINE_ITEM_TTL_DAYS", 30),
        )
        store = QuarantineStore(public_key, self.repository, limits, self.quarantine_limiter)
        hindsight = HindsightGateway(
            os.environ.get("HINDSIGHT_BASE_URL", "http://hindsight:8888"),
            os.environ.get("HINDSIGHT_API_KEY"),
            hindsight_timeout_ms,
            integer_env("HINDSIGHT_MAX_RESPONSE_BYTES", 4 * 1024 * 1024, minimum=1),
        )
        self.hindsight = hindsight
        hconfig = HindsightLimitConfig(
            retain_writer_max=integer_env("HINDSIGHT_RETAIN_RATE_LIMIT_WRITER_MAX", 30, minimum=1),
            retain_global_max=integer_env("HINDSIGHT_RETAIN_RATE_LIMIT_GLOBAL_MAX", 300, minimum=1),
            recall_writer_max=integer_env("HINDSIGHT_RECALL_RATE_LIMIT_WRITER_MAX", 120, minimum=1),
            recall_global_max=integer_env(
                "HINDSIGHT_RECALL_RATE_LIMIT_GLOBAL_MAX", 1200, minimum=1
            ),
            rate_limit_window_ms=integer_env("HINDSIGHT_RATE_LIMIT_WINDOW_MS", 60_000, minimum=1),
            max_retain_items=integer_env("HINDSIGHT_RETAIN_MAX_ITEMS", 100, minimum=1),
            max_retain_content_bytes=integer_env(
                "HINDSIGHT_RETAIN_MAX_CONTENT_BYTES", 524_288, minimum=1
            ),
            max_recall_query_bytes=integer_env(
                "HINDSIGHT_RECALL_MAX_QUERY_BYTES", 32_768, minimum=1
            ),
            max_recall_max_tokens=integer_env("HINDSIGHT_RECALL_MAX_TOKENS", 8192, minimum=1),
        )
        registry = load_registry(os.environ.get("MEMORY_ROUTER_REGISTRY"))
        hindsight_limiter = (
            self.quarantine_limiter if is_postgres(database_url) else InMemoryRateLimiter()
        )
        hindsight_limits = HindsightLimits(hconfig, hindsight_limiter)
        self.policy = RouterPolicy(registry, hindsight, hindsight_limits, store, self.repository)
        self.admin = QuarantineAdminService(
            self.repository,
            hindsight,
            registry,
            hindsight_limits,
            integer_env("QUARANTINE_MAX_POSTPONES", 3),
            self.review_stale_seconds,
        )
        self.auditor = AuthFailureAuditor(store)
        interval = integer_env("QUARANTINE_SWEEP_INTERVAL_SECONDS", 3600)
        retention = integer_env("QUARANTINE_EVENT_RETENTION_DAYS", 90)
        if interval > 0:
            self.sweeper = asyncio.create_task(self._sweep_loop(interval, retention))

    async def stop(self) -> None:
        if self.sweeper:
            self.sweeper.cancel()
            try:
                await self.sweeper
            except asyncio.CancelledError:
                pass
        if self.hindsight:
            await self.hindsight.close()
        if self.rate_limit_database:
            await self.rate_limit_database.close()
        if self.repository:
            await self.repository.close()

    async def _sweep_loop(self, interval: int, retention_days: int) -> None:
        repository = _require_runtime(self.repository, "repository")
        while True:
            await asyncio.sleep(interval)
            at = _now()
            try:
                await recover_interrupted(repository, at, self.review_stale_seconds)
                await sweep_expired(repository, at)
                if retention_days > 0:
                    cutoff = (
                        (datetime.now(UTC) - timedelta(days=retention_days))
                        .isoformat(timespec="milliseconds")
                        .replace("+00:00", "Z")
                    )
                    await prune_events_before(repository, cutoff, at)
            except Exception as exc:
                logger.error("quarantine sweeper failed error_type=%s", type(exc).__name__)


runtime = Runtime()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await runtime.start()
    try:
        yield
    finally:
        await runtime.stop()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(HttpError)
async def http_error_handler(_: Request, exc: HttpError) -> JSONResponse:
    if isinstance(exc, HindsightGatewayError):
        logger.warning(
            "upstream request failed request_id=%s details=%s", current_request_id(), exc.details()
        )
    return JSONResponse(exc.body(), status_code=exc.status, headers=exc.headers)


@app.exception_handler(Exception)
async def unhandled_handler(_: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "request failed request_id=%s error_type=%s", current_request_id(), type(exc).__name__
    )
    return JSONResponse({"error": "internal error"}, status_code=500)


async def _json_body(request: Request) -> Any:
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > runtime.max_body_bytes:
        raise HttpError(413, "payload_too_large", "payload too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > runtime.max_body_bytes:
            raise HttpError(413, "payload_too_large", "payload too large")
    if not body:
        return {}
    try:
        value = json.loads(
            bytes(body), parse_constant=lambda raw: (_ for _ in ()).throw(ValueError(raw))
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HttpError(400, "invalid_json", "invalid JSON body") from exc
    _assert_json_depth(value)
    return value


async def _auth_failure_rate(route_group: str) -> None:
    try:
        await runtime.auth_limiter.consume_many(
            [(f"auth-failure:{route_group}", runtime.auth_failure_max, runtime.auth_failure_window)]
        )
    except HttpError as exc:
        if exc.status == 429:
            raise HttpError(429, "auth_rate_limited", "too many authentication failures") from exc
        raise


async def _router_auth(request: Request) -> bool:
    if router_authorized(
        request.headers.get("authorization"), runtime.router_token, runtime.allow_anonymous
    ):
        return True
    await _auth_failure_rate("router")
    auditor = _require_runtime(runtime.auditor, "auth auditor")
    await auditor.record("router")
    return False


async def _admin_auth(request: Request, scope: str) -> bool:
    authorization = request.headers.get("authorization")
    if admin_authorized(authorization, scope, runtime.admin_tokens):
        return True
    if admin_token_recognized(authorization, runtime.admin_tokens):
        return False
    await _auth_failure_rate("admin")
    auditor = _require_runtime(runtime.auditor, "auth auditor")
    await auditor.record("admin")
    return False


async def _admin_rate(method: str) -> None:
    request_class = "read" if method in {"GET", "HEAD"} else "write"
    maximum = runtime.admin_read_max if request_class == "read" else runtime.admin_write_max
    try:
        await runtime.admin_limiter.consume_many(
            [(f"admin:{request_class}", maximum, runtime.admin_window)]
        )
    except HttpError as exc:
        if exc.status == 429:
            raise HttpError(
                429, "admin_rate_limited", f"too many admin {request_class} requests"
            ) from exc
        raise


@app.get("/health/live")
async def health_live() -> dict[str, str | float]:
    return {
        "status": "alive",
        "version": _ROUTER_VERSION,
        "uptime_seconds": round(time.monotonic() - _PROCESS_START, 1),
    }


async def _database_health(repository: QuarantineRepository) -> bool:
    try:
        await repository.ping()
    except Exception:
        return False
    return True


async def _hindsight_health(hindsight: HindsightGateway) -> tuple[bool, Any]:
    try:
        return True, await hindsight.health()
    except Exception:
        return False, None


async def _health_ready_response() -> Response:
    try:
        repository = _require_runtime(runtime.repository, "repository")
        hindsight = _require_runtime(runtime.hindsight, "Hindsight gateway")
        database_healthy, hindsight_check = await asyncio.gather(
            _database_health(repository), _hindsight_health(hindsight)
        )
    except Exception:
        return JSONResponse({"status": "unhealthy"}, status_code=503)
    hindsight_healthy, hindsight_response = hindsight_check
    if not database_healthy or not hindsight_healthy:
        return JSONResponse({"status": "unhealthy"}, status_code=503)
    return JSONResponse(hindsight_response)


@app.get("/health")
@app.get("/health/ready")
async def health_ready() -> Response:
    return await _health_ready_response()


@app.get("/ready")
async def ready() -> Response:
    return await _health_ready_response()


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"],
)
async def dispatch(path: str, request: Request) -> Response:
    del path
    pathname = _raw_pathname(request)
    method = request.method
    if pathname.startswith("/admin/"):
        if not await _admin_auth(request, _scope(method, pathname)):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        await _admin_rate(method)
        admin = _require_runtime(runtime.admin, "admin service")
        if method == "GET" and pathname == "/admin/quarantine/queue":
            params = request.query_params
            if len(params.getlist("limit")) > 1 or len(params.getlist("offset")) > 1:
                raise HttpError(400, "invalid_query", "limit or offset is invalid")
            try:
                limit = int(params.get("limit", "100"))
                offset = int(params.get("offset", "0"))
            except ValueError as exc:
                raise HttpError(400, "invalid_query", "invalid integer query parameter") from exc
            if not 1 <= limit <= 500 or offset < 0:
                raise HttpError(400, "invalid_query", "integer query parameter out of range")
            return JSONResponse(await admin.list_queue(limit, offset))
        if method == "GET" and pathname == "/admin/quarantine/stats":
            return JSONResponse(await admin.stats())
        if method == "POST" and pathname == "/admin/quarantine/cleanup":
            body = await _json_body(request)
            if not isinstance(body, dict):
                raise HttpError(400, "invalid_request", "cleanup body must be an object")
            return JSONResponse(await admin.cleanup(body))
        match = re.fullmatch(
            r"/admin/quarantine/items/([^/]+)(?:/(approve|reject|postpone))?", pathname
        )
        if match:
            item_id, action = _decode_path_segment(match.group(1)), match.group(2)
            if method == "GET" and action is None:
                return JSONResponse(await admin.read_item(item_id))
            if method == "POST" and action == "approve":
                body = await _json_body(request)
                if not isinstance(body, dict):
                    raise HttpError(400, "invalid_request", "approve body must be an object")
                return JSONResponse(await admin.approve(item_id, body))
            if method == "POST" and action == "reject":
                return JSONResponse(await admin.reject(item_id))
            if method == "POST" and action == "postpone":
                return JSONResponse(await admin.postpone(item_id))
        return JSONResponse({"error": "admin_endpoint_not_found"}, status_code=404)

    if method == "GET" and pathname == "/version":
        hindsight = _require_runtime(runtime.hindsight, "Hindsight gateway")
        return JSONResponse(await hindsight.version())
    if not await _router_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    policy = _require_runtime(runtime.policy, "router policy")
    match = re.fullmatch(r"/v1/default/banks/([^/]+)/memories(?:/(recall))?", pathname)
    if method == "POST" and match:
        writer_id, action = _decode_path_segment(match.group(1)), match.group(2)
        if action == "recall":
            body = parse_recall_body(await _json_body(request))
            policy.limits.assert_recall_bounds(body)
            return JSONResponse(await policy.recall(writer_id, body))
        body = parse_retain_body(await _json_body(request))
        policy.limits.assert_retain_bounds(body)
        return JSONResponse(await policy.retain(writer_id, body))
    return JSONResponse(await policy.deny_endpoint(method, pathname), status_code=404)