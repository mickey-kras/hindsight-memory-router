from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from typing import Any
from urllib.parse import unquote

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .admin import QuarantineAdminService
from .auth import AuthFailureAuditor, admin_authorized, admin_token_recognized, router_authorized
from .canonical import assert_json_depth
from .config import (
    RouterSettings,
    assert_auth_environment,
    assert_no_private_key_environment,
    load_registry,
    load_settings,
    secret_value,
    validate_settings,
)
from .db import (
    PostgresDatabase,
    create_database,
    is_postgres,
    validate_storage,
)
from .errors import HttpError, rate_limit_error
from .hindsight import HindsightGateway, HindsightGatewayError, hindsight_log_fields
from .limits import HindsightLimitConfig, HindsightLimits
from .logging import configure_logging, log_event
from .maintenance import prune_events_before, sweep_expired
from .observability import current_duration_ms, current_request_id
from .openclaw import (
    OpenClawFacade,
    shutdown_facade_scan_executor_async,
    start_facade_scan_executor,
)
from .policy import RouterPolicy
from .principal_gate import authenticate_principal
from .principals import (
    PrincipalResolver,
    PrincipalSession,
    load_principal_registry,
    scope_limit_operation,
)
from .probes import _CACHE_MAX_STALENESS_SECONDS as _CACHE_MAX_STALENESS_SECONDS
from .probes import _READINESS_CACHE_SECONDS as _READINESS_CACHE_SECONDS
from .probes import _cached_probe_response as _cached_probe_response
from .probes import _CachedProbe as _CachedProbe
from .probes import _ProbeCache as _ProbeCache
from .probes import _readiness as _readiness
from .probes import _readiness_log_state as _readiness_log_state
from .probes import _ReadinessLogState as _ReadinessLogState
from .probes import _storage_readiness_log_state as _storage_readiness_log_state
from .probes import _version as _version
from .quarantine_store import QuarantineLimits, QuarantineStore
from .rate_limit import (
    ConcurrencyLeaseUnavailable,
    InMemoryRateLimiter,
    PostgresConcurrencyLimiter,
    PostgresRateLimiter,
)
from .repository import QuarantineRepository
from .request_dispatch import (
    EMPTY_BODY,
    AuthenticatedRequestDispatcher,
    DispatchDependencies,
)
from .review_repository import REVIEW_STALE_SECONDS, recover_interrupted
from .timestamps import iso_format, iso_now

logger = logging.getLogger(__name__)
configure_logging()
_PERCENT_DOT = re.compile(r"%2e", re.I)
_INVALID_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MAX_JSON_DEPTH = 64
_MAX_PATH_PROBE_DECODES = 8
_PROCESS_START = time.monotonic()
_READINESS_FAILURE_LOG_INTERVAL_SECONDS = 60.0
_EMPTY_BODY = EMPTY_BODY
_AUTH_AUDITOR_COMPONENT = "auth auditor"
_AUTHENTICATION_REQUIRED = {
    "error": "unauthorized",
    "message": "authentication required",
}
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


def _route_class(request: Request) -> str:
    path = _raw_pathname(request)
    if path in {"/health", "/health/ready", "/ready"}:
        return "readiness"
    if path == "/health/live":
        return "liveness"
    if path == "/version":
        return "version"
    if path.startswith("/admin/"):
        return "admin"
    if re.fullmatch(r"/v1/default/banks/[^/]+/memories(?:/recall)?", path):
        return "memory"
    if path.startswith("/v1/default/banks/"):
        return "openclaw"
    return "unmatched"


_REFRESH_TIMEOUT_SECONDS = 15.0
_DEPENDENCY_PROBE_TIMEOUT_SECONDS = 10.0


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
        decoded = unquote(value, encoding="utf-8", errors="strict")
    except ValueError as exc:
        raise HttpError(
            400, "invalid_path_encoding", "path segment contains malformed percent-encoding"
        ) from exc
    probe = decoded
    for _ in range(_MAX_PATH_PROBE_DECODES):
        if "/" in probe:
            raise HttpError(400, "invalid_path_segment", "encoded path separators are not allowed")
        if probe in {".", ".."}:
            raise HttpError(400, "invalid_path_segment", "dot path segments are not allowed")
        try:
            next_probe = unquote(probe, encoding="utf-8", errors="strict")
        except ValueError:
            break
        if next_probe == probe:
            break
        probe = next_probe
    else:
        if probe in {".", ".."}:
            raise HttpError(400, "invalid_path_segment", "dot path segments are not allowed")
        raise HttpError(400, "invalid_path_encoding", "path segment has excessive nested encoding")
    return decoded


def _assert_json_depth(value: Any) -> None:
    try:
        assert_json_depth(value, max_depth=_MAX_JSON_DEPTH)
    except ValueError as exc:
        raise HttpError(400, "json_too_deep", "JSON nesting depth exceeds limit") from exc


class Runtime:
    def __init__(self, settings: RouterSettings | None = None) -> None:
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
        self.principal_limiter: Any = InMemoryRateLimiter()
        self.principal_concurrency_limiter: PostgresConcurrencyLimiter | None = None
        self.principal_concurrency: dict[tuple[str, str], int] = {}
        self.sweeper: asyncio.Task[None] | None = None
        self.settings: RouterSettings | None = None
        self.principal_resolver: PrincipalResolver | None = None
        if settings is None:
            self._apply_request_settings(RouterSettings.model_construct())
        else:
            self.configure(settings)
        self.review_stale_seconds = REVIEW_STALE_SECONDS

    def configure(self, settings: RouterSettings) -> None:
        settings = validate_settings(settings)
        self.settings = settings
        self._apply_request_settings(settings)

    def _apply_request_settings(self, settings: RouterSettings) -> None:
        self.max_body_bytes = settings.memory_router_max_body_bytes
        self.router_token = secret_value(settings.memory_router_token)
        self.allow_anonymous = settings.memory_router_allow_anonymous
        self.principal_resolver = (
            PrincipalResolver(load_principal_registry(settings.memory_router_principals))
            if settings.memory_router_principals
            else None
        )
        self.admin_tokens = {
            "legacy": secret_value(settings.memory_router_admin_token),
            "read": secret_value(settings.memory_router_admin_read_token),
            "review": secret_value(settings.memory_router_admin_review_token),
            "cleanup": secret_value(settings.memory_router_admin_cleanup_token),
        }
        self.admin_read_max = settings.memory_router_admin_rate_limit_read_max
        self.admin_write_max = settings.memory_router_admin_rate_limit_write_max
        self.admin_window = settings.memory_router_admin_rate_limit_window_ms
        self.auth_failure_max = settings.memory_router_auth_failure_rate_limit_max
        self.auth_failure_window = settings.memory_router_auth_failure_rate_limit_window_ms

    async def start(self) -> None:
        settings = self.settings or load_settings()
        self.configure(settings)
        assert_no_private_key_environment()
        assert_auth_environment(settings)
        hindsight_timeout_ms = settings.hindsight_timeout_ms
        self.review_stale_seconds = max(
            REVIEW_STALE_SECONDS, (hindsight_timeout_ms + 999) // 1000 + 30
        )
        database_url = settings.quarantine_database_url
        self.database = await create_database(database_url)
        self.repository = QuarantineRepository(self.database)
        await validate_storage(self.database, database_url)
        await recover_interrupted(self.repository, _now(), self.review_stale_seconds)
        if is_postgres(database_url):
            self.rate_limit_database = PostgresDatabase(database_url, max_size=5)
            await self.rate_limit_database.initialize()
            self.quarantine_limiter = PostgresRateLimiter(self.rate_limit_database)
            await self.quarantine_limiter.initialize()
            self.principal_limiter = self.quarantine_limiter
            self.principal_concurrency_limiter = PostgresConcurrencyLimiter(
                self.rate_limit_database
            )
            await self.principal_concurrency_limiter.initialize()
        else:
            self.quarantine_limiter = InMemoryRateLimiter()
            self.principal_limiter = InMemoryRateLimiter()
            self.principal_concurrency_limiter = None
        self.auth_limiter = InMemoryRateLimiter()
        limits = QuarantineLimits(
            max_item_bytes=settings.quarantine_max_item_bytes,
            max_pending_items=settings.quarantine_max_pending_items,
            max_pending_items_per_writer=settings.quarantine_max_pending_items_per_writer,
            max_encrypted_bytes=settings.quarantine_max_encrypted_bytes,
            rate_limit_max=settings.quarantine_rate_limit_max,
            rate_limit_window_ms=settings.quarantine_rate_limit_window_ms,
            rate_limit_global_max=settings.quarantine_rate_limit_global_max,
            distinct_family_limit_max=settings.quarantine_distinct_family_limit_max,
            requarantine_ops_max=settings.quarantine_requarantine_ops_max,
            item_ttl_days=settings.quarantine_item_ttl_days,
        )
        store = QuarantineStore(
            settings.quarantine_public_key, self.repository, limits, self.quarantine_limiter
        )
        hindsight = HindsightGateway(
            settings.hindsight_base_url,
            secret_value(settings.hindsight_api_key),
            hindsight_timeout_ms,
            settings.hindsight_max_response_bytes,
        )
        self.hindsight = hindsight
        hconfig = HindsightLimitConfig(
            retain_writer_max=settings.hindsight_retain_rate_limit_writer_max,
            retain_global_max=settings.hindsight_retain_rate_limit_global_max,
            recall_writer_max=settings.hindsight_recall_rate_limit_writer_max,
            recall_global_max=settings.hindsight_recall_rate_limit_global_max,
            rate_limit_window_ms=settings.hindsight_rate_limit_window_ms,
            max_retain_items=settings.hindsight_retain_max_items,
            max_retain_content_bytes=settings.hindsight_retain_max_content_bytes,
            max_recall_query_bytes=settings.hindsight_recall_max_query_bytes,
            max_recall_max_tokens=settings.hindsight_recall_max_tokens,
        )
        registry = load_registry(settings.memory_router_registry)
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
            settings.quarantine_max_postpones,
            self.review_stale_seconds,
        )
        self.auditor = AuthFailureAuditor(store)
        interval = settings.quarantine_sweep_interval_seconds
        retention = settings.quarantine_event_retention_days
        if interval > 0:
            self.sweeper = asyncio.create_task(self._sweep_loop(interval, retention))

    async def stop(self) -> None:
        if self.sweeper:
            self.sweeper.cancel()
            (sweeper_result,) = await asyncio.gather(self.sweeper, return_exceptions=True)
            if isinstance(sweeper_result, BaseException) and not isinstance(
                sweeper_result, asyncio.CancelledError
            ):
                raise sweeper_result
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
                    cutoff = iso_format(datetime.now(UTC) - timedelta(days=retention_days))
                    await prune_events_before(repository, cutoff, at)
            except Exception as exc:
                log_event(
                    logger,
                    "error",
                    "quarantine_sweeper_failed",
                    operation="quarantine_maintenance",
                    error_kind="unexpected",
                    error=exc,
                    outcome="failed",
                )


runtime = Runtime()


async def _cleanup_failed_start(*, runtime_started: bool, scanner_started: bool) -> None:
    if scanner_started:
        await _run_startup_cleanup(shutdown_facade_scan_executor_async())
    if runtime_started:
        await _run_startup_cleanup(runtime.stop())


async def _run_startup_cleanup(cleanup: Awaitable[None]) -> None:
    (result,) = await asyncio.gather(cleanup, return_exceptions=True)
    if isinstance(result, BaseException):
        log_event(
            logger,
            "error",
            "application_stop_failed",
            operation="shutdown",
            error_kind="unexpected",
            error=result,
            outcome="failed",
        )


async def _stop_runtime(*, reraise: bool) -> None:
    try:
        await runtime.stop()
    except BaseException as exc:
        log_event(
            logger,
            "error",
            "application_stop_failed",
            operation="shutdown",
            error_kind="unexpected",
            error=exc,
            outcome="failed",
        )
        if reraise:
            raise
    finally:
        await shutdown_facade_scan_executor_async()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    runtime_started = False
    scanner_start_attempted = False
    try:
        await runtime.start()
        runtime_started = True
        scanner_start_attempted = True
        await asyncio.to_thread(start_facade_scan_executor)
    except BaseException as exc:
        await _cleanup_failed_start(
            runtime_started=runtime_started,
            scanner_started=scanner_start_attempted,
        )
        log_event(
            logger,
            "error",
            "application_start_failed",
            operation="startup",
            error_kind="unexpected",
            error=exc,
            outcome="failed",
        )
        raise
    log_event(logger, "info", "application_started", operation="startup", outcome="healthy")
    try:
        yield
    except BaseException:
        await _stop_runtime(reraise=False)
        raise
    else:
        await _stop_runtime(reraise=True)


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(HttpError)
async def http_error_handler(request: Request, exc: HttpError) -> JSONResponse:
    if isinstance(exc, HindsightGatewayError):
        route_class = _route_class(request)
        log_event(
            logger,
            "warning",
            "hindsight_request_failed",
            **hindsight_log_fields(exc),
            error=exc,
            outcome="failed",
            route_class=route_class,
        )
    return JSONResponse(exc.body(), status_code=exc.status, headers=exc.headers)


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    log_event(
        logger,
        "error",
        "request_failed",
        request_id=current_request_id(),
        operation="request",
        request_method=request.method,
        error_kind="unexpected",
        error=exc,
        http_status=500,
        outcome="failed",
        request_duration_ms=current_duration_ms(),
        route_class=_route_class(request),
    )
    return JSONResponse({"error": "internal error"}, status_code=500)


async def _json_body(
    request: Request, *, empty_as_none: bool = False, max_bytes: int | None = None
) -> Any:
    body_limit = (
        runtime.max_body_bytes if max_bytes is None else min(runtime.max_body_bytes, max_bytes)
    )
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > body_limit:
        raise HttpError(413, "payload_too_large", "payload too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > body_limit:
            raise HttpError(413, "payload_too_large", "payload too large")
    if not body:
        return _EMPTY_BODY if empty_as_none else {}
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
        if exc.status != 429:
            raise
        raise rate_limit_error(
            code="auth_rate_limited", message="too many authentication failures"
        ) from exc


async def _principal_rate(session: PrincipalSession, scope: str, route_class: str) -> None:
    operation = scope_limit_operation(scope)
    limit = session.limits[operation]
    try:
        await runtime.principal_limiter.consume_many(
            [
                (
                    f"principal:{session.principal_id}:{operation}",
                    limit.rate_limit_max,
                    limit.rate_limit_window_ms,
                )
            ]
        )
    except HttpError as exc:
        if exc.status != 429:
            raise
        retry_after = max(1, (limit.rate_limit_window_ms + 999) // 1000)
        log_event(
            logger,
            "warning",
            "principal_throttled",
            request_id=current_request_id(),
            operation="authorize",
            error_kind="rate-limit",
            http_status=429,
            outcome="degraded",
            route_class=route_class,
            principal=session.principal_id,
            scope=scope,
        )
        raise rate_limit_error(
            code="principal_rate_limited",
            message="too many requests for principal",
            headers={"retry-after": str(retry_after)},
        ) from exc
    except Exception as exc:
        log_event(
            logger,
            "error",
            "principal_rate_unavailable",
            request_id=current_request_id(),
            operation="consume-principal-rate",
            error_kind="storage",
            error=exc,
            http_status=503,
            outcome="degraded",
            route_class=route_class,
            principal=session.principal_id,
            scope=scope,
        )
        raise HttpError(
            503,
            "principal_rate_unavailable",
            "principal rate control is temporarily unavailable",
            headers={"retry-after": "1"},
        ) from exc


def _principal_concurrency_acquire(
    session: PrincipalSession, scope: str, route_class: str
) -> tuple[str, str]:
    operation = scope_limit_operation(scope)
    key = (session.principal_id, operation)
    active = runtime.principal_concurrency.get(key, 0)
    if active >= session.limits[operation].concurrency_max:
        log_event(
            logger,
            "warning",
            "principal_throttled",
            request_id=current_request_id(),
            operation="authorize",
            error_kind="rate-limit",
            http_status=429,
            outcome="degraded",
            route_class=route_class,
            principal=session.principal_id,
            scope=scope,
        )
        raise rate_limit_error(
            code="principal_concurrency_limited",
            message="too many concurrent requests for principal",
            headers={"retry-after": "1"},
        )
    runtime.principal_concurrency[key] = active + 1
    return key


def _principal_concurrency_release(key: tuple[str, str]) -> None:
    active = runtime.principal_concurrency.get(key, 0) - 1
    if active > 0:
        runtime.principal_concurrency[key] = active
    else:
        runtime.principal_concurrency.pop(key, None)


async def _with_principal_concurrency(
    request: Request,
    session: PrincipalSession,
    scope: str,
    operation: Callable[[], Awaitable[Any]],
) -> Any:
    distributed = runtime.principal_concurrency_limiter
    if distributed is not None:
        operation_name = scope_limit_operation(scope)
        bucket = f"{session.principal_id}:{operation_name}"
        try:
            return await distributed.run(
                bucket, session.limits[operation_name].concurrency_max, operation
            )
        except HttpError as exc:
            if exc.code != "principal_concurrency_limited":
                raise
            log_event(
                logger,
                "warning",
                "principal_throttled",
                request_id=current_request_id(),
                operation="authorize",
                error_kind="rate-limit",
                http_status=429,
                outcome="degraded",
                route_class=_route_class(request),
                principal=session.principal_id,
                scope=scope,
            )
            raise rate_limit_error(
                code="principal_concurrency_limited",
                message="too many concurrent requests for principal",
                headers=exc.headers,
            ) from exc
        except ConcurrencyLeaseUnavailable as exc:
            log_event(
                logger,
                "error",
                "principal_concurrency_unavailable",
                request_id=current_request_id(),
                operation="manage-concurrency-lease",
                error_kind="storage",
                error=exc,
                http_status=503,
                outcome="degraded",
                route_class=_route_class(request),
                principal=session.principal_id,
                scope=scope,
            )
            raise HttpError(
                503,
                "principal_concurrency_unavailable",
                "principal concurrency control is temporarily unavailable",
                headers={"retry-after": "1"},
            ) from exc
    key = _principal_concurrency_acquire(session, scope, _route_class(request))
    try:
        return await operation()
    finally:
        _principal_concurrency_release(key)


async def _router_auth(request: Request) -> bool:
    if router_authorized(
        request.headers.get("authorization"), runtime.router_token, runtime.allow_anonymous
    ):
        return True
    auditor = _require_runtime(runtime.auditor, _AUTH_AUDITOR_COMPONENT)
    route_class = _route_class(request)
    auditor.log_failure(route_class)
    await _auth_failure_rate("router")
    await auditor.persist("router", route_class)
    return False


async def _admin_auth(request: Request, scope: str) -> bool:
    authorization = request.headers.get("authorization")
    if admin_authorized(authorization, scope, runtime.admin_tokens):
        return True
    auditor = _require_runtime(runtime.auditor, _AUTH_AUDITOR_COMPONENT)
    route_class = _route_class(request)
    if admin_token_recognized(authorization, runtime.admin_tokens):
        auditor.log_failure(route_class)
        await _auth_failure_rate("admin")
        return False
    auditor.log_failure(route_class)
    await _auth_failure_rate("admin")
    await auditor.persist("admin", route_class)
    return False


async def _admin_rate(method: str) -> None:
    request_class = "read" if method in {"GET", "HEAD"} else "write"
    maximum = runtime.admin_read_max if request_class == "read" else runtime.admin_write_max
    try:
        await runtime.admin_limiter.consume_many(
            [(f"admin:{request_class}", maximum, runtime.admin_window)]
        )
    except HttpError as exc:
        if exc.status != 429:
            raise
        raise rate_limit_error(
            code="admin_rate_limited", message=f"too many admin {request_class} requests"
        ) from exc


@app.get("/health/live")
async def health_live() -> dict[str, str | float]:
    return {
        "status": "alive",
        "version": _ROUTER_VERSION,
        "uptime_seconds": round(time.monotonic() - _PROCESS_START, 1),
    }


async def _database_health(
    repository: QuarantineRepository,
) -> tuple[bool, Exception | None, float]:
    started = time.monotonic()
    try:
        await asyncio.wait_for(repository.ping(), timeout=_DEPENDENCY_PROBE_TIMEOUT_SECONDS)
    except Exception as exc:
        duration_ms = round((time.monotonic() - started) * 1000, 3)
        _storage_readiness_log_state.record(exc, duration_ms)
        return False, exc, duration_ms
    duration_ms = round((time.monotonic() - started) * 1000, 3)
    _storage_readiness_log_state.record(None, duration_ms)
    return True, None, duration_ms


async def _hindsight_health(
    hindsight: HindsightGateway,
) -> tuple[bool, Any, Exception | None, float]:
    started = time.monotonic()
    try:
        response = await asyncio.wait_for(
            hindsight.health(), timeout=_DEPENDENCY_PROBE_TIMEOUT_SECONDS
        )
    except Exception as exc:
        duration_ms = round((time.monotonic() - started) * 1000, 3)
        _readiness_log_state.record(exc, duration_ms)
        return False, None, exc, duration_ms
    duration_ms = round((time.monotonic() - started) * 1000, 3)
    _readiness_log_state.record(None, duration_ms)
    return True, response, None, duration_ms


async def _health_ready_response() -> Response:
    async def refresh() -> Response:
        status_code = 200
        payload: Any
        try:
            repository = _require_runtime(runtime.repository, "repository")
            hindsight = _require_runtime(runtime.hindsight, "Hindsight gateway")
            database_check, hindsight_check = await asyncio.wait_for(
                asyncio.gather(_database_health(repository), _hindsight_health(hindsight)),
                timeout=_REFRESH_TIMEOUT_SECONDS,
            )
            database_healthy, _, _ = database_check
            hindsight_healthy, hindsight_response, _, _ = hindsight_check
            if not database_healthy or not hindsight_healthy:
                status_code, payload = 503, {"status": "unhealthy"}
            else:
                payload = hindsight_response
        except Exception:
            status_code, payload = 503, {"status": "unhealthy"}
        return JSONResponse(payload, status_code=status_code)

    return await _readiness.get(refresh)


@app.get("/health")
@app.get("/health/ready")
async def health_ready() -> Response:
    return await _health_ready_response()


@app.get("/ready")
async def ready() -> Response:
    return await _health_ready_response()


async def _version_response() -> Response:
    async def refresh() -> Response:
        try:
            hindsight = _require_runtime(runtime.hindsight, "Hindsight gateway")
            payload = await asyncio.wait_for(hindsight.version(), timeout=_REFRESH_TIMEOUT_SECONDS)
        except TimeoutError as exc:
            error = HindsightGatewayError("timeout", operation="version", method="GET")
            error.__cause__ = exc
            return _version_failure(error)
        except HindsightGatewayError as exc:
            return _version_failure(exc)
        except Exception as exc:
            error = HindsightGatewayError(
                "network", operation="version", method="GET", client_status=503
            )
            error.__cause__ = exc
            return _version_failure(error)
        return JSONResponse(payload)

    return await _version.get(refresh)


def _version_failure(error: HindsightGatewayError) -> Response:
    log_event(
        logger,
        "warning",
        "hindsight_request_failed",
        **hindsight_log_fields(error),
        error=error,
        outcome="failed",
        route_class="version",
    )
    return JSONResponse(error.body(), status_code=error.status, headers=error.headers)


async def _admin_queue_response(request: Request, admin: QuarantineAdminService) -> Response:
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


async def _admin_body(request: Request, action: str) -> dict[str, Any]:
    body = await _json_body(request)
    if not isinstance(body, dict):
        raise HttpError(400, "invalid_request", f"{action} body must be an object")
    return body


async def _admin_item_response(
    request: Request,
    admin: QuarantineAdminService,
    method: str,
    match: re.Match[str],
) -> Response | None:
    item_id = _decode_path_segment(match.group(1))
    action = match.group(2)
    if method == "GET" and action is None:
        return JSONResponse(await admin.read_item(item_id))
    if method == "POST":
        if action == "approve":
            body = await _admin_body(request, "approve")
            return JSONResponse(await admin.approve(item_id, body))
        if action == "reject":
            return JSONResponse(await admin.reject(item_id))
        if action == "postpone":
            return JSONResponse(await admin.postpone(item_id))
    return None


async def _authorized_admin_response(
    request: Request,
    admin: QuarantineAdminService,
    pathname: str,
    method: str,
) -> Response:
    if method == "GET" and pathname == "/admin/quarantine/queue":
        return await _admin_queue_response(request, admin)
    if method == "GET" and pathname == "/admin/quarantine/stats":
        return JSONResponse(await admin.stats())
    if method == "POST" and pathname == "/admin/quarantine/cleanup":
        return JSONResponse(await admin.cleanup(await _admin_body(request, "cleanup")))
    match = re.fullmatch(
        r"/admin/quarantine/items/([^/]+)(?:/(approve|reject|postpone))?", pathname
    )
    if match is not None:
        response = await _admin_item_response(request, admin, method, match)
        if response is not None:
            return response
    return JSONResponse({"error": "admin_endpoint_not_found"}, status_code=404)


async def _dispatch_admin(request: Request, pathname: str, method: str) -> Response | None:
    if not pathname.startswith("/admin/"):
        return None
    if not await _admin_auth(request, _scope(method, pathname)):
        return JSONResponse(_AUTHENTICATION_REQUIRED, status_code=401)
    await _admin_rate(method)
    admin = _require_runtime(runtime.admin, "admin service")
    return await _authorized_admin_response(request, admin, pathname, method)


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"],
)
async def dispatch(path: str, request: Request) -> Response:
    del path
    pathname = _raw_pathname(request)
    method = request.method
    admin_response = await _dispatch_admin(request, pathname, method)
    if admin_response is not None:
        return admin_response

    if method == "GET" and pathname == "/version":
        return await _version_response()
    route_class = _route_class(request)
    principal: PrincipalSession | None = None
    if runtime.principal_resolver is not None:
        principal = await authenticate_principal(
            request,
            resolver=_require_runtime(runtime.principal_resolver, "principal resolver"),
            auditor=_require_runtime(runtime.auditor, _AUTH_AUDITOR_COMPONENT),
            route_class=route_class,
            on_failure=lambda: _auth_failure_rate("router"),
        )
        if principal is None:
            return JSONResponse(_AUTHENTICATION_REQUIRED, status_code=401)
    elif not await _router_auth(request):
        return JSONResponse(_AUTHENTICATION_REQUIRED, status_code=401)
    dispatcher = AuthenticatedRequestDispatcher(
        DispatchDependencies(
            policy=_require_runtime(runtime.policy, "router policy"),
            resolver=runtime.principal_resolver,
            hindsight=runtime.hindsight,
            json_body=_json_body,
            principal_rate=_principal_rate,
            concurrency=_with_principal_concurrency,
            decode_path_segment=_decode_path_segment,
            facade_factory=OpenClawFacade,
        )
    )
    return await dispatcher.dispatch(request, pathname, method, principal, route_class)
