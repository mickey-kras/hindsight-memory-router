# Application logs

Memory Router writes one JSON object per line to standard output. Uvicorn access logs remain disabled.

Every record includes `event`, `level`, `logger`, and `timestamp`. Optional fields are bounded to `request_id`, `operation`, `request_method`, `upstream_method`, `error_kind`, `upstream_status`, `http_status`, `outcome`, `request_duration_ms`, `operation_duration_ms`, `route_class`, `writer_id`, `reason`, and `timeout_ms`. `http_status` is always an integer; `outcome` is one of `failed`, `degraded`, `healthy`, or `unhealthy`. `route_class` is one of `readiness`, `liveness`, `version`, `admin`, `memory`, `openclaw`, or `unmatched`; it is never a request path.

Readiness results are cached and concurrent probes are coalesced. Two consecutive observations are required before a state transition is recorded. `hindsight_readiness_failed` is warning-level and `hindsight_readiness_recovered` is info-level; readiness events are limited to one per minute per replica. Multi-worker deployments can therefore emit one transition per worker.

Event catalog: `application_started` (info); `hindsight_readiness_recovered` (info); `authentication_failed`, `bank_unavailable`, `hindsight_readiness_failed`, `hindsight_request_failed`, `openclaw_security_audit_failed`, `quarantine_placeholder_unavailable`, `quarantine_write_unavailable`, and `recall_supplemental_audit_unavailable` (warning); `authentication_audit_failed`, `quarantine_sweeper_failed`, and `request_failed` (error). Route security audit warnings and upstream/request failures are rate-limited; alert routing should page on error events, alert on sustained warning events, and treat info events as lifecycle context.

`structlog` 26.1.0 is pinned with hashes in the runtime lock. Dependency updates use reviewed lock refreshes rather than selecting releases during builds.

Logs intentionally exclude credentials, headers, URLs, paths, request and response bodies, memory or query text, decrypted quarantine data, exception messages, and stack traces. Use `request_id` to correlate a router failure with Hindsight without enabling access logs or adding payload data.
