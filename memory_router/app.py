from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import metrics, metrics_http, probes_http
from .admin import AdminActor, QuarantineAdminService
from .auth import (
    AuthFailureAuditor,
    admin_authorized,
    admin_token_recognized,
    admin_token_scope,
    router_authorized,
)
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
from .db import Database, PostgresDatabase, create_backend, validate_storage
from .errors import HttpError, rate_limit_error
from .hindsight import HindsightGateway, HindsightGatewayError, hindsight_log_fields
from .key_wrap import SidecarWrapProvider, WrapProvider
from .limits import HindsightLimitConfig, HindsightLimits
from .logging import configure_logging, log_event
from .maintenance import prune_events_before, sweep_expired
from .observability import current_duration_ms, current_request_id
from .openclaw import (
    shutdown_facade_scan_executor_async,
    start_facade_scan_executor,
)
from .paths import _decode_path_segment, _raw_pathname, _route_class
from .policy import RouterPolicy
from .principal_gate import (
    PrincipalAdminDeps,
    authenticate_principal,
    principal_admin_metadata_response,
    principal_token_present,
)
from .principals import (
    PrincipalResolver,
    PrincipalSession,
    load_principal_registry,
    scope_limit_operation,
)
from .quarantine_store import QuarantineLimits, QuarantineStore
from .rate_limit import (
    Bucket,
    ConcurrencyLeaseUnavailable,
    ConcurrencyLimiter,
    InMemoryConcurrencyLimiter,
    InMemoryRateLimiter,
    RateLimiter,
)
from .repository import QuarantineRepository, parse_queue_filter
from .request_dispatch import (
    EMPTY_BODY,
    AuthenticatedRequestDispatcher,
    DispatchDependencies,
)
from .review_repository import REVIEW_STALE_SECONDS, recover_interrupted
from .timestamps import iso_format, iso_now

logger = logging.getLogger(__name__)
configure_logging()
_MAX_JSON_DEPTH = 64
_AUTH_AUDITOR_COMPONENT = "auth auditor"
_AUTHENTICATION_REQUIRED = {
    "error": "unauthorized",
    "message": "authentication required",
}


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


def _build_wrap_provider(settings: RouterSettings) -> SidecarWrapProvider | None:
    if settings.quarantine_wrap_provider == "https-sidecar":
        return SidecarWrapProvider(
            settings.quarantine_wrap_sidecar_url,
            secret_value(settings.quarantine_wrap_sidecar_token),
            settings.quarantine_wrap_sidecar_timeout_ms,
            settings.quarantine_wrap_sidecar_name,
            settings.quarantine_wrap_sidecar_version,
            settings.quarantine_wrap_sidecar_wrapped_key_bytes,
        )
    return None


def _assert_json_depth(value: Any) -> None:
    try:
        assert_json_depth(value, max_depth=_MAX_JSON_DEPTH)
    except ValueError as exc:
        raise HttpError(400, "json_too_deep", "JSON nesting depth exceeds limit") from exc


class Runtime:
    def __init__(self, settings: RouterSettings | None = None) -> None:
        self.database: Database | None = None
        self.rate_limit_database: PostgresDatabase | None = None
        self.repository: QuarantineRepository | None = None
        self.hindsight: HindsightGateway | None = None
        self.wrap_provider: WrapProvider | None = None
        self.policy: RouterPolicy | None = None
        self.admin: QuarantineAdminService | None = None
        self.auditor: AuthFailureAuditor | None = None
        self.quarantine_limiter: RateLimiter = InMemoryRateLimiter()
        self.admin_limiter: RateLimiter = InMemoryRateLimiter()
        self.auth_limiter: RateLimiter = InMemoryRateLimiter()
        self.auth_prefilter = InMemoryRateLimiter()
        self.principal_limiter: RateLimiter = InMemoryRateLimiter()
        self.principal_concurrency_limiter: ConcurrencyLimiter = InMemoryConcurrencyLimiter()
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
        self.metrics_enabled = settings.memory_router_metrics_enabled
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
        self.auth_prefilter = InMemoryRateLimiter()
        assert_no_private_key_environment()
        assert_auth_environment(settings)
        hindsight_timeout_ms = settings.hindsight_timeout_ms
        self.review_stale_seconds = max(
            REVIEW_STALE_SECONDS, (hindsight_timeout_ms + 999) // 1000 + 30
        )
        database_url = settings.quarantine_database_url
        backend = await create_backend(database_url)
        self.database = backend.database
        self.rate_limit_database = backend.rate_limit_database
        self.repository = QuarantineRepository(self.database)
        await validate_storage(self.database, database_url)
        await recover_interrupted(self.repository, iso_now(), self.review_stale_seconds)
        self.quarantine_limiter = backend.rate_limiter
        self.admin_limiter = backend.create_limiter()
        self.auth_limiter = backend.create_limiter()
        self.principal_limiter = backend.create_limiter()
        self.principal_concurrency_limiter = (
            backend.concurrency_limiter or InMemoryConcurrencyLimiter()
        )
        limits = QuarantineLimits(
            max_item_bytes=settings.quarantine_max_item_bytes,
            max_pending_items=settings.quarantine_max_pending_items,
            max_pending_items_per_writer=settings.quarantine_max_pending_items_per_writer,
            max_pending_items_per_bank=settings.quarantine_max_pending_items_per_bank,
            max_encrypted_bytes=settings.quarantine_max_encrypted_bytes,
            rate_limit_max=settings.quarantine_rate_limit_max,
            rate_limit_window_ms=settings.quarantine_rate_limit_window_ms,
            rate_limit_global_max=settings.quarantine_rate_limit_global_max,
            distinct_family_limit_max=settings.quarantine_distinct_family_limit_max,
            requarantine_ops_max=settings.quarantine_requarantine_ops_max,
            item_ttl_days=settings.quarantine_item_ttl_days,
        )
        self.wrap_provider = _build_wrap_provider(settings)
        store = QuarantineStore(
            settings.quarantine_public_key,
            self.repository,
            limits,
            self.quarantine_limiter,
            self.wrap_provider,
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
        hindsight_limiter = backend.create_limiter()
        hindsight_limits = HindsightLimits(hconfig, hindsight_limiter)
        self.policy = RouterPolicy(registry, hindsight, hindsight_limits, store, self.repository)
        self.admin = QuarantineAdminService(
            self.repository,
            hindsight,
            registry,
            hindsight_limits,
            settings.quarantine_max_postpones,
            self.review_stale_seconds,
            self.principal_resolver,
        )
        self.auditor = AuthFailureAuditor(store)
        interval = settings.quarantine_sweep_interval_seconds
        retention = settings.quarantine_event_retention_days
        export_path = settings.quarantine_event_export_path or None
        if interval > 0:
            self.sweeper = asyncio.create_task(self._sweep_loop(interval, retention, export_path))

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
        if self.wrap_provider:
            await self.wrap_provider.close()
        if self.rate_limit_database:
            await self.rate_limit_database.close()
        if self.repository:
            await self.repository.close()

    async def _sweep_loop(
        self, interval: int, retention_days: int, export_path: str | None = None
    ) -> None:
        repository = _require_runtime(self.repository, "repository")
        while True:
            await asyncio.sleep(interval)
            at = iso_now()
            try:
                await recover_interrupted(repository, at, self.review_stale_seconds)
                await sweep_expired(repository, at)
                if retention_days > 0:
                    cutoff = iso_format(datetime.now(UTC) - timedelta(days=retention_days))
                    await prune_events_before(repository, cutoff, at, export_path)
            except Exception as exc:
                metrics.record_sweeper_failure()
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
    route_class = _route_class(request)
    if exc.status == 429:
        metrics.record_rate_limited(route_class)
    elif exc.status == 507:
        metrics.record_capacity_rejection(route_class)
    if isinstance(exc, HindsightGatewayError):
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
        return EMPTY_BODY if empty_as_none else {}
    try:
        value = json.loads(bytes(body), parse_constant=_reject_json_constant)
    except (ValueError, RecursionError) as exc:
        raise HttpError(400, "invalid_json", "invalid JSON body") from exc
    _assert_json_depth(value)
    return value


def _reject_json_constant(raw: str) -> None:
    raise ValueError(raw)


async def _auth_failure_rate(route_group: str) -> None:
    try:
        await runtime.auth_prefilter.consume_many(
            [
                Bucket(
                    f"auth-failure:{route_group}",
                    runtime.auth_failure_max,
                    runtime.auth_failure_window,
                )
            ]
        )
        await runtime.auth_limiter.consume_many(
            [
                Bucket(
                    f"auth-failure:{route_group}",
                    runtime.auth_failure_max,
                    runtime.auth_failure_window,
                )
            ]
        )
    except HttpError as exc:
        if exc.status != 429:
            raise
        raise rate_limit_error(
            code="auth_rate_limited", message="too many authentication failures"
        ) from exc
    except Exception as exc:
        raise _rate_storage_unavailable("auth", exc) from exc


def _rate_storage_unavailable(scope: str, error: Exception) -> HttpError:
    code = f"{scope}_rate_unavailable"
    log_event(
        logger,
        "error",
        code,
        request_id=current_request_id(),
        operation="authenticate" if scope == "auth" else "authorize",
        error_kind="storage",
        error=error,
        http_status=503,
        outcome="degraded",
    )
    return HttpError(
        503,
        code,
        f"{scope} rate control is temporarily unavailable",
        headers={"retry-after": "1"},
    )


async def _principal_rate(session: PrincipalSession, scope: str, route_class: str) -> None:
    operation = scope_limit_operation(scope)
    limit = session.limits[operation]
    try:
        await runtime.principal_limiter.consume_many(
            [
                Bucket(
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


async def _with_principal_concurrency[T](
    request: Request,
    session: PrincipalSession,
    scope: str,
    operation: Callable[[], Awaitable[T]],
) -> T:
    operation_name = scope_limit_operation(scope)
    bucket = f"{session.principal_id}:{operation_name}"
    try:
        return await runtime.principal_concurrency_limiter.run(
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
    recognized = admin_token_recognized(authorization, runtime.admin_tokens)
    auditor.log_failure(route_class)
    await _auth_failure_rate("admin")
    if not recognized:
        await auditor.persist("admin", route_class)
    return False


async def _admin_rate(method: str) -> None:
    request_class = "read" if method in {"GET", "HEAD"} else "write"
    maximum = runtime.admin_read_max if request_class == "read" else runtime.admin_write_max
    try:
        await runtime.admin_limiter.consume_many(
            [Bucket(f"admin:{request_class}", maximum, runtime.admin_window)]
        )
    except HttpError as exc:
        if exc.status != 429:
            raise
        raise rate_limit_error(
            code="admin_rate_limited", message=f"too many admin {request_class} requests"
        ) from exc
    except Exception as exc:
        raise _rate_storage_unavailable("admin", exc) from exc


def _probes_deps() -> probes_http.ProbesDeps:
    return probes_http.ProbesDeps(
        repository=runtime.repository,
        hindsight=runtime.hindsight,
        router_token=runtime.router_token,
        allow_anonymous=runtime.allow_anonymous,
        resolver=runtime.principal_resolver,
        auditor=runtime.auditor,
        auth_failure_rate=_auth_failure_rate,
    )


@app.get("/health/live")
async def health_live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health")
@app.get("/health/ready")
async def health_ready(request: Request) -> Response:
    return await probes_http.readiness_probe_response(request, _probes_deps())


@app.get("/ready")
async def ready(request: Request) -> Response:
    return await probes_http.readiness_probe_response(request, _probes_deps())


async def _admin_queue_response(
    request: Request, admin: QuarantineAdminService, scoped_banks: tuple[str, ...] | None = None
) -> Response:
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
    filter_ = parse_queue_filter(params)
    if scoped_banks is not None:
        filter_ = filter_.with_bank_scope(scoped_banks)
    return JSONResponse(
        await admin.list_queue(limit, offset, filter_ if filter_.active() else None)
    )


async def _admin_body(request: Request, action: str) -> dict[str, Any]:
    body = await _json_body(request)
    if not isinstance(body, dict):
        raise HttpError(400, "invalid_request", f"{action} body must be an object")
    return body


async def _approve_item_response(
    request: Request, admin: QuarantineAdminService, item_id: str, actor: AdminActor
) -> Response:
    body = await _admin_body(request, "approve")
    return JSONResponse(await admin.approve(item_id, body, actor))


async def _reject_item_response(
    request: Request, admin: QuarantineAdminService, item_id: str, actor: AdminActor
) -> Response:
    return JSONResponse(await admin.reject(item_id, actor))


async def _postpone_item_response(
    request: Request, admin: QuarantineAdminService, item_id: str, actor: AdminActor
) -> Response:
    return JSONResponse(await admin.postpone(item_id, actor))


async def _reconcile_item_response(
    request: Request, admin: QuarantineAdminService, item_id: str, actor: AdminActor
) -> Response:
    body = await _admin_body(request, "reconcile")
    return JSONResponse(await admin.reconcile(item_id, body, actor))


_ADMIN_ITEM_ACTIONS: dict[
    str, Callable[[Request, QuarantineAdminService, str, AdminActor], Awaitable[Response]]
] = {
    "approve": _approve_item_response,
    "reject": _reject_item_response,
    "postpone": _postpone_item_response,
    "reconcile": _reconcile_item_response,
}


async def _admin_item_response(
    request: Request,
    admin: QuarantineAdminService,
    method: str,
    match: re.Match[str],
    actor: AdminActor,
) -> Response | None:
    item_id = _decode_path_segment(match.group(1))
    action = match.group(2)
    if method == "GET" and action is None:
        return JSONResponse(await admin.read_item(item_id))
    if method == "POST" and action in {"approve", "reject", "postpone", "reconcile"}:
        return await _ADMIN_ITEM_ACTIONS[action](request, admin, item_id, actor)
    return None


async def _authorized_admin_response(
    request: Request,
    admin: QuarantineAdminService,
    pathname: str,
    method: str,
    actor: AdminActor,
) -> Response:
    if method == "GET" and pathname == "/admin/quarantine/queue":
        return await _admin_queue_response(request, admin)
    if method == "GET" and pathname == "/admin/quarantine/stats":
        return JSONResponse(await admin.stats())
    if method == "POST" and pathname == "/admin/quarantine/cleanup":
        return JSONResponse(await admin.cleanup(await _admin_body(request, "cleanup"), actor))
    match = re.fullmatch(
        r"/admin/quarantine/items/([^/]+)(?:/(approve|reject|postpone|reconcile))?", pathname
    )
    if match is not None:
        response = await _admin_item_response(request, admin, method, match, actor)
        if response is not None:
            return response
    return JSONResponse({"error": "admin_endpoint_not_found"}, status_code=404)


async def _principal_admin_response(request: Request, pathname: str, method: str) -> Response:
    deps = PrincipalAdminDeps(
        resolver=_require_runtime(runtime.principal_resolver, "principal resolver"),
        auditor=_require_runtime(runtime.auditor, _AUTH_AUDITOR_COMPONENT),
        admin=_require_runtime(runtime.admin, "admin service"),
        on_auth_failure=lambda: _auth_failure_rate("admin"),
        principal_rate=_principal_rate,
        queue_response=_admin_queue_response,
    )
    return await principal_admin_metadata_response(request, pathname, method, deps)


async def _dispatch_admin(request: Request, pathname: str, method: str) -> Response | None:
    if not pathname.startswith("/admin/"):
        return None
    authorization = request.headers.get("authorization")
    scope = _scope(method, pathname)
    if not admin_authorized(authorization, scope, runtime.admin_tokens):
        if runtime.principal_resolver is not None and principal_token_present(authorization):
            return await _principal_admin_response(request, pathname, method)
        if not await _admin_auth(request, scope):
            return JSONResponse(_AUTHENTICATION_REQUIRED, status_code=401)
    token_scope = admin_token_scope(authorization, scope, runtime.admin_tokens)
    if token_scope is None:
        raise RuntimeError("admin request authorized without a matching admin token slot")
    await _admin_rate(method)
    admin = _require_runtime(runtime.admin, "admin service")
    actor = AdminActor(token_scope=token_scope)
    response = await _authorized_admin_response(request, admin, pathname, method, actor)
    if token_scope == "legacy":  # noqa: S105  # nosec B105 - token scope label, not a credential
        response.headers["Deprecation"] = "true"
    return response


async def _dispatch_metrics(request: Request, pathname: str, method: str) -> Response | None:
    if not metrics_http.metrics_route_enabled(pathname, method, runtime.metrics_enabled):
        return None
    return await metrics_http.metrics_endpoint_response(
        request,
        metrics_http.MetricsDeps(
            admin_tokens=runtime.admin_tokens,
            resolver=runtime.principal_resolver,
            auditor=_require_runtime(runtime.auditor, _AUTH_AUDITOR_COMPONENT),
            repository=_require_runtime(runtime.repository, "repository"),
            admin_auth=_admin_auth,
            admin_rate=_admin_rate,
            principal_rate=_principal_rate,
            auth_failure_rate=_auth_failure_rate,
        ),
    )


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

    metrics_response = await _dispatch_metrics(request, pathname, method)
    if metrics_response is not None:
        return metrics_response

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
    if method == "GET" and pathname == "/version":
        response = await probes_http.version_response(runtime.hindsight)
    else:
        response = await AuthenticatedRequestDispatcher(
            DispatchDependencies(
                policy=_require_runtime(runtime.policy, "router policy"),
                resolver=runtime.principal_resolver,
                hindsight=runtime.hindsight,
                json_body=_json_body,
                principal_rate=_principal_rate,
                concurrency=_with_principal_concurrency,
                decode_path_segment=_decode_path_segment,
            )
        ).dispatch(request, pathname, method, principal, route_class)
    if principal is None and runtime.router_token is not None:
        response.headers["Deprecation"] = "true"
    return response
