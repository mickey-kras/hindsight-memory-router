# Application logs

Memory Router writes one JSON object per line to standard output. Uvicorn access logs remain disabled.

Operational events use a bounded schema: `event`, `request_id`, `operation`, `method`, `error_kind`, `upstream_status`, `status`, `duration_ms`, and `route_class`. Fields that do not apply are omitted. `route_class` is a fixed category such as `readiness`, `liveness`, `version`, `admin`, `memory`, `openclaw`, or `unmatched`; it is never the request path.

Hindsight readiness emits `hindsight_readiness_failed` on the first failure or when the failure kind changes. An unchanged failure repeats at most once per minute. `hindsight_readiness_recovered` is emitted once when Hindsight becomes healthy again.

Logs intentionally exclude credentials, headers, URLs, paths, request and response bodies, memory or query text, decrypted quarantine data, exception messages, and stack traces. Use `request_id` to correlate a router failure with Hindsight without enabling access logs or adding payload data.
