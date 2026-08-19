# Application logs

One bounded JSON object is written to stdout per event. Required fields: `event`, `level`, `logger`, `timestamp`.

Optional fields: `request_id`, `operation`, `request_method`, `upstream_method`, `error_kind`, `error_fingerprint`, `upstream_status`, `http_status`, `outcome`, `request_duration_ms`, `operation_duration_ms`, `route_class`, `writer_id`, `reason`, `timeout_ms`, `suppressed`.

`request_id` and `writer_id` are capped at 128 characters. `error_fingerprint` is an allowlisted exception class or opaque raise-site hash.

## Values

- `error_kind`: `capacity`, `conflict`, `http`, `invalid-credentials`, `invalid-response`, `network`, `payload-too-large`, `rate-limit`, `response-too-large`, `storage`, `timeout`, `unexpected`
- `outcome`: `failed`, `degraded`, `healthy`, `unhealthy`
- `route_class`: `readiness`, `liveness`, `version`, `admin`, `memory`, `openclaw`, `unmatched`
- `operation`: `authenticate`, `configuration`, `health`, `invalidate_memory`, `openclaw_bank`, `openclaw_config`, `openclaw_mental-models`, `openclaw_reflect`, `quarantine_maintenance`, `recall`, `request`, `retain`, `security_audit`, `shutdown`, `startup`, `storage_health`, `version`
- `reason`: `admin-cleanup-token-missing`, `admin-read-token-missing`, `admin-review-token-missing`, `anonymous-mode`, `application-shutdown`, `application-startup`, `asgi-application-error`, `direct-stdlib-log`, `http-protocol-error`, `legacy-admin-token`, `openclaw-suspicious-provider-response`, `openclaw-suspicious-request`, `openclaw-unknown-writer`, `reserved-field`, `router-token-missing`, `runtime-other`, `server-finished`, `server-running`, `server-started`, `server-stopping`, `unregistered-event`

## Events

- info: `application_started`, `hindsight_readiness_recovered`, `storage_readiness_recovered`
- warning: `authentication_failed`, `bank_unavailable`, `configuration_warning`, `hindsight_readiness_failed`, `hindsight_request_failed`, `quarantine_placeholder_unavailable`, `quarantine_write_unavailable`, `storage_readiness_failed`
- error: `application_start_failed`, `application_stop_failed`, `authentication_audit_failed`, `logging_contract_violation`, `openclaw_security_audit_failed`, `quarantine_sweeper_failed`, `recall_supplemental_audit_unavailable`, `request_failed`
- Uvicorn: `runtime_message` with a bounded `reason`; original text is dropped

## Safety

Never logged: credentials, headers, URLs, paths, bodies, memory/query text, decrypted quarantine data, exception messages, or stack traces. `httpx` and `httpcore` logs below warning are suppressed. Uvicorn access logs are disabled.

Use `python -m memory_router` or the `memory-router` script. Direct Uvicorn launch is unsupported. Embedders must call `configure_logging()` after their logging setup and run Uvicorn with `log_config=None` and `access_log=False`. Pre-attached `uvicorn.error` handlers remain deployer-owned; they must use the same safe JSON format.

## Throttling and probe cache

- High-volume events: one per `(event, route_class, error_kind)` per minute. The next record includes `suppressed=N`.
- Uvicorn noise: one per `reason` per minute.
- Readiness failures: one per dependency/error kind per minute after two matching observations. Recoveries also require two observations.
- Readiness and anonymous `/version`: cache success and failure for one second; serve stale data for at most five seconds during one bounded refresh; cold concurrent callers get 503.
- Auth failures are logged before rate limiting. Only admitted attempts are persisted.
- Each worker maintains its own cache and throttle state.

Not logged per request: quarantine 413/429/507 responses, general 429 responses, or aged `review_side_effect_started` items. Track these with metrics; see [Production readiness](production-readiness.md).

`structlog==26.1.0` and all runtime packages are hash-pinned.
