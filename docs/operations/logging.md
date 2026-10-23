# Application logs

[Documentation](../README.md) | [Repository](../../README.md)

The logger writes one bounded JSON object to stdout per event.
The mandatory fields are `event`, `level`, `logger`, and `timestamp`.

Optional fields: `request_id`, `operation`, `maintenance_phase`, `request_method`, `upstream_method`, `error_kind`, `error_fingerprint`, `upstream_status`, `http_status`, `outcome`, `request_duration_ms`, `operation_duration_ms`, `route_class`, `writer_id`, `reason`, `timeout_ms`, `suppressed`.

Text caps are 128 for request IDs, writer IDs, and logger names, 64 for operation names, and 16 for methods.
`request_id` accepts `[A-Za-z0-9._:-]` from the client.
Clients must not put secrets in request IDs.
The router replaces invalid request IDs with generated IDs.
Writer registry IDs must match `[A-Za-z0-9._:-]{1,128}` and cannot be `.` or `..`.
Invalid registries fail startup.

The logger fingerprints other invalid writer IDs and logger names.
`error_fingerprint` is an allowlisted exception class or opaque raise-site hash.

The logger drops unknown fields and invalid numbers.
Invalid enums use their safe fallback.
The logger drops records that it cannot safely format.
Logging never stops application flow.
If the pipeline cannot emit a record, it writes a bounded `{"event":"logging_write_failed","count":N}` marker to stderr.
The marker has a monotonic per-process count and no event fields.

## Values

- `error_kind`: `capacity`, `conflict`, `http`, `invalid-credentials`, `invalid-response`, `network`, `payload-too-large`, `rate-limit`, `response-too-large`, `shutdown`, `storage`, `timeout`, `unexpected`, `worker-crash`
- `outcome`: `failed`, `degraded`, `healthy`, `unhealthy`
- `route_class`: `readiness`, `liveness`, `version`, `admin`, `memory`, `openclaw`, `unmatched`
- `operation`: values in `memory_router/logging_contract.py`, plus `facade_scan` and `openclaw_<allowlist operation>`
- `maintenance_phase`: `session-prune`, `review-recovery`, `expiry`, `event-retention`. The logger drops other values.
- `reason`: `admin-cleanup-token-missing`, `admin-read-token-missing`, `admin-review-token-missing`, `anonymous-mode`, `application-shutdown`, `application-startup`, `asgi-application-error`, `direct-stdlib-log`, `http-protocol-error`, `legacy-admin-token`, `legacy-router-token`, `openclaw-suspicious-provider-response`, `openclaw-suspicious-request`, `openclaw-unknown-writer`, `reserved-field`, `router-token-missing`, `runtime-other`, `server-finished`, `server-running`, `server-started`, `server-stopping`, `unregistered-event`

## Events

- Level `info`: `application_started`, `hindsight_readiness_recovered`, `storage_readiness_recovered`
- Level `warning`: `authentication_failed`, `bank_unavailable`, `configuration_warning`, `facade_scan_failed`, `hindsight_readiness_failed`, `hindsight_request_failed`, `principal_throttled`, `quarantine_placeholder_unavailable`, `quarantine_write_unavailable`, `readiness_orchestration_failed`, `storage_readiness_failed`
- Level `error`: `application_start_failed`, `application_stop_failed`, `authentication_audit_failed`, `logging_contract_violation`, `openclaw_security_audit_failed`, `principal_concurrency_release_failed`, `principal_concurrency_unavailable`, `principal_rate_unavailable`, `quarantine_sweeper_failed`, `recall_aggregate_audit_unavailable`, `recall_supplemental_audit_unavailable`, `request_failed`
- Uvicorn: `runtime_message` with a bounded `reason`. The logger drops the original text.

## Safety

The logger never records credentials, headers, URLs, paths, bodies, memory or query text, decrypted quarantine data, exception messages, or stack traces. It suppresses `httpx` and `httpcore` logs below the `warning` level. Uvicorn access logs are off.

Use `python -m memory_router` or the `memory-router` script.
If you start the Uvicorn CLI directly, it skips `RequestIdMiddleware`.
Programmatic Uvicorn defaults can replace safe handlers.
For embedded deployments, call `configure_logging()` after logging setup.
Use `log_config=None` and `access_log=False`.

Deployers are responsible for pre-attached `uvicorn.error` handlers.
These handlers must use the safe JSON format.

## Throttling and probe cache

- High-volume events: one per `(event, route_class, error_kind)` per minute. The next record includes `suppressed=N`.
- `quarantine_sweeper_failed` adds its allowlisted `maintenance_phase` to that throttle key.
  Each failed phase stays visible with its own suppressed count. Session pruning and event retention continue independently after failures. Expiry runs only after a successful review recovery. The sweeper failure metric counts failed iterations once, even if several phases fail. Cancellation adds no failure count or event.
- Uvicorn noise at the `warning` and `error` levels: one per `reason` per minute. The logger never throttles critical records.
- The log records a change of dependency readiness only after two equal observations. An unexpected failure of the readiness orchestration emits `readiness_orchestration_failed` immediately. The per-category minute throttle above applies to the next records. HTTP readiness responses use each probe result immediately.
- Readiness and anonymous `/version` cache success and failure for one second.
  They serve stale data for at most five seconds during one bounded refresh.
  Concurrent callers without a cached result get 503.
- The logger writes each authentication failure before the in-memory failure gate of the process.
  The router stores only admitted invalid-token attempts.
- Each worker keeps its own cache and throttle state.

The logger never throttles `logging_contract_violation`.
This keeps developer contract errors visible.

Not logged per request: successful authentications, legacy-mode memory operations, quarantine 413/429/507 responses, general 429 responses, or aged `review_side_effect_started` items. Track these with metrics. See [Production readiness](production-readiness.md).

`structlog==26.1.0` and all runtime packages are hash-pinned.

