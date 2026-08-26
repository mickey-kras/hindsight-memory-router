# Application logs

One bounded JSON object is written to stdout per event. Required fields: `event`, `level`, `logger`, `timestamp`.

Optional fields: `request_id`, `operation`, `request_method`, `upstream_method`, `error_kind`, `error_fingerprint`, `upstream_status`, `http_status`, `outcome`, `request_duration_ms`, `operation_duration_ms`, `route_class`, `writer_id`, `reason`, `timeout_ms`, `suppressed`.

Text caps: request and writer IDs 128, logger 128, operation 64, methods 16. `request_id` accepts client-provided `[A-Za-z0-9._:-]`; clients must not put secrets in it. Invalid request IDs are replaced by generated IDs. Writer registry IDs must match `[A-Za-z0-9._:-]{1,128}` and cannot be `.` or `..`; invalid registries fail startup. Other invalid writer IDs and logger names are fingerprinted. `error_fingerprint` is an allowlisted exception class or opaque raise-site hash.

Unknown fields and invalid numbers are dropped. Invalid enums use their safe fallback. Records that cannot be safely formatted are dropped; logging never fails application flow.

## Values

- `error_kind`: `capacity`, `conflict`, `http`, `invalid-credentials`, `invalid-response`, `network`, `payload-too-large`, `rate-limit`, `response-too-large`, `storage`, `timeout`, `unexpected`, `worker-crash`
- `outcome`: `failed`, `degraded`, `healthy`, `unhealthy`
- `route_class`: `readiness`, `liveness`, `version`, `admin`, `memory`, `openclaw`, `unmatched`
- `operation`: core operations in `logging_contract.OPERATIONS`, plus `facade_scan` and `openclaw_<allowlist operation>` for every facade route
- `reason`: `admin-cleanup-token-missing`, `admin-read-token-missing`, `admin-review-token-missing`, `anonymous-mode`, `application-shutdown`, `application-startup`, `asgi-application-error`, `direct-stdlib-log`, `http-protocol-error`, `legacy-admin-token`, `openclaw-suspicious-provider-response`, `openclaw-suspicious-request`, `openclaw-unknown-writer`, `reserved-field`, `router-token-missing`, `runtime-other`, `server-finished`, `server-running`, `server-started`, `server-stopping`, `unregistered-event`

## Events

- info: `application_started`, `hindsight_readiness_recovered`, `storage_readiness_recovered`
- warning: `authentication_failed`, `bank_unavailable`, `configuration_warning`, `facade_scan_failed`, `hindsight_readiness_failed`, `hindsight_request_failed`, `quarantine_placeholder_unavailable`, `quarantine_write_unavailable`, `storage_readiness_failed`
- error: `application_start_failed`, `application_stop_failed`, `authentication_audit_failed`, `logging_contract_violation`, `openclaw_security_audit_failed`, `quarantine_sweeper_failed`, `recall_supplemental_audit_unavailable`, `request_failed`
- Uvicorn: `runtime_message` with a bounded `reason`; original text is dropped

## Safety

Never logged: credentials, headers, URLs, paths, bodies, memory/query text, decrypted quarantine data, exception messages, or stack traces. `httpx` and `httpcore` logs below warning are suppressed. Uvicorn access logs are disabled.

Use `python -m memory_router` or the `memory-router` script. Direct Uvicorn CLI launch skips `RequestIdMiddleware`; programmatic Uvicorn defaults may replace safe handlers. Embedders must call `configure_logging()` after their logging setup and use `log_config=None` and `access_log=False`. Pre-attached `uvicorn.error` handlers remain deployer-owned and must use the safe JSON format.

## Throttling and probe cache

- High-volume events: one per `(event, route_class, error_kind)` per minute. The next record includes `suppressed=N`.
- Uvicorn warning/error noise: one per `reason` per minute. Critical records are never throttled.
- Readiness log transitions require two matching observations. HTTP readiness responses use each probe result immediately.
- Readiness and anonymous `/version`: cache success and failure for one second; serve stale data for at most five seconds during one bounded refresh; cold concurrent callers get 503.
- Auth failures are logged before the process-local in-memory failure gate. Only admitted invalid-token attempts are persisted.
- Each worker maintains its own cache and throttle state.

`logging_contract_violation` is intentionally unthrottled so developer contract bugs fail loud.

Not logged per request: quarantine 413/429/507 responses, general 429 responses, or aged `review_side_effect_started` items. Track these with metrics; see [Production readiness](production-readiness.md).

`structlog==26.1.0` and all runtime packages are hash-pinned.
