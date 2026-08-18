# Application logs

Memory Router writes one bounded JSON object per line to standard output. Uvicorn access logs remain disabled. `httpx` and `httpcore` request logs are suppressed below warning so upstream URLs, paths, and query strings cannot enter the application stream.

Every record includes `event`, `level`, `logger`, and `timestamp`. Optional fields are `request_id`, `operation`, `request_method`, `upstream_method`, `error_kind`, `error_fingerprint`, `upstream_status`, `http_status`, `outcome`, `request_duration_ms`, `operation_duration_ms`, `route_class`, `writer_id`, `reason`, `timeout_ms`, and `suppressed`. `writer_id` is capped at 128 characters. `error_fingerprint` is an allowlisted exception class or an opaque raise-site hash; exception messages and tracebacks are never emitted.

Bounded enums:

- `error_kind`: `capacity`, `conflict`, `http`, `invalid-credentials`, `invalid-response`, `network`, `payload-too-large`, `rate-limit`, `response-too-large`, `storage`, `timeout`, or `unexpected`;
- `outcome`: `failed`, `degraded`, `healthy`, or `unhealthy`;
- `route_class`: `readiness`, `liveness`, `version`, `admin`, `memory`, `openclaw`, or `unmatched`;
- `operation`: `authenticate`, `configuration`, `health`, `invalidate_memory`, `openclaw_bank`, `openclaw_config`, `openclaw_mental-models`, `openclaw_reflect`, `quarantine_maintenance`, `recall`, `request`, `retain`, `security_audit`, `startup`, `storage_health`, or `version`.

Event catalog:

- info: `application_started`, `hindsight_readiness_recovered`, `storage_readiness_recovered`;
- warning: `authentication_failed`, `bank_unavailable`, `configuration_warning`, `hindsight_readiness_failed`, `hindsight_request_failed`, `openclaw_security_audit_failed`, `quarantine_placeholder_unavailable`, `quarantine_write_unavailable`, `recall_supplemental_audit_unavailable`, `storage_readiness_failed`;
- error: `application_start_failed`, `authentication_audit_failed`, `logging_contract_violation`, `quarantine_sweeper_failed`, `request_failed`.

Uvicorn lifecycle and protocol records use `event=runtime_message` plus a bounded `reason` and retain Uvicorn's level; their original prose is not passed through. Malformed-request protocol warnings are rate-limited. When Gunicorn or another process manager installs or reroutes `uvicorn.error` handlers after application import, that deployer owns their format; configure its error handler as JSON or keep the supported direct Uvicorn launch.

Readiness results are cached, concurrent probes are coalesced, and a stale cached response is served while one refresh is in flight. Two consecutive observations confirm a dependency transition. Failure events are emitted at most once per minute per dependency and error kind. Every confirmed recovery is emitted immediately so alerts can clear. Multi-worker deployments can emit one transition per worker.

High-volume failure events are throttled per event, route class, and error kind. The next emitted record includes `suppressed=N` when records were dropped during the interval.

`structlog` 26.1.0 is pinned with hashes in the runtime lock. The pinned base image supplies pip; all installed runtime packages are hash-verified.

Logs intentionally exclude credentials, headers, URLs, paths, request and response bodies, memory or query text, decrypted quarantine data, exception messages, and stack traces. Use `request_id` and `error_fingerprint` for correlation.

Quarantine admission failures (413/429/507), general rate-limit rejections, and aged `review_side_effect_started` items remain part of the metrics/alerts follow-up in [Production readiness](production-readiness.md); this PR does not add per-request log events for them.
