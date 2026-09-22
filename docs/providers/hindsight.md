# Hindsight upstream

Hindsight is the only memory backend implemented by Memory Router today.

Current topology:

```text
OpenClaw (Hindsight plugin) -> Memory Router -> Hindsight
```

Default endpoint:

```text
http://hindsight:8888
```

Override it with `HINDSIGHT_BASE_URL`. Set `HINDSIGHT_API_KEY` when the Hindsight deployment requires authentication.

The default HTTP endpoint is for an isolated Docker network shared only by Memory Router and Hindsight. Plaintext `http` upstream URLs fail at startup unless the host is private (RFC1918/link-local, loopback, `*.internal`, or a single-label docker service name); exempt hosts keep the `insecure-hindsight-transport` startup warning. Set `HINDSIGHT_REQUIRE_SECURE_TRANSPORT=true` to require HTTPS for every upstream, especially when sending `HINDSIGHT_API_KEY`.

## Facade policy

- Routes are allowlisted in `memory_router/facade_routes.py`; `openapi/openclaw.json` is the contract.
- `{bank_id}` is a writer ID. Memory Router resolves the Hindsight bank.
- GET (including `stats?refresh=true`), reflect, dry-run extract, and dry-run refresh use recall quotas. Other writes use retain quotas.
- Bodies use `MEMORY_ROUTER_MAX_BODY_BYTES` (default: 1 MiB). Retain, recall, and dry-run extract have stricter limits.
- Request bodies, queries, and facade responses share four process worker slots with no unbounded queue. Request body scan budgets remain five seconds; queries allow 256 pairs and ten seconds. Workers terminate after the applicable budgets plus one second; callers wait at most one additional second. Responses allow 256 KiB, 8,192 fields, and 30 seconds.
- Request worker, capacity, hard timeout, or shutdown failure returns `503 request_scan_unavailable`; response worker, capacity, or scan-limit failure returns `503 facade_scan_unavailable`. Both include `Retry-After: 1` and do not quarantine the operational failure. Request scanner findings retain their existing block/quarantine behavior.
- Unknown query parameters are dropped before scanning.

Webhooks, file transfer, import/export, metrics, provider-credential LLM health probes, cross-writer listings, and deprecated upstream routes are denied and quarantined.

## Failure mapping

`HINDSIGHT_TIMEOUT_MS` must be positive.

| Hindsight result | Router response |
| --- | --- |
| Timeout | `504 hindsight_timeout` |
| Facade 4xx except 401/403 | Same status, sanitized `hindsight_http_error` |
| Facade response over 256 KiB | `502 hindsight_response_too_large` |
| Unsafe facade response | `502 hindsight_unsafe_response` |
| Unexpected 2xx status or disallowed empty success body | `502 hindsight_invalid_response` |
| Request scanner worker failure, busy capacity, hard timeout, or shutdown | `503 request_scan_unavailable` |
| Facade response scanner worker failure, busy capacity, or field/time limit | `503 facade_scan_unavailable` |
| Redirect, 401/403, 5xx, network, or malformed response | Typed 502 |

Upstream response bodies are never returned.

Optional bodies treat no body and JSON `null` the same. Required bodies must be JSON objects. Bodyless upstream requests omit `Content-Type`.

A typed recall failure affects only the Hindsight read bank that failed. If all configured read banks fail, recall returns empty results. Unexpected application/database failures still propagate rather than being hidden as Hindsight degradation.

## Consumption limits

Retain and recall have separate per-writer and global sliding-window budgets. Request bounds return `413`; quota exhaustion returns `429 hindsight_rate_limited` with `Retry-After`.

PostgreSQL-backed limits are shared across router replicas. Authenticated requests consume quota before content scanning, so blocked/quarantined scans, upstream failures, and response-scan failures count. Unknown writers and cheap structural failures do not.

Other memory backends are not supported.
