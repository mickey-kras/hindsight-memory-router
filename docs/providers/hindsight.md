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

The default HTTP endpoint is for an isolated Docker network shared only by Memory Router and Hindsight. Use HTTPS whenever Hindsight is routed outside that private network, especially when sending `HINDSIGHT_API_KEY`.

## Facade policy

- Allowlist: `memory_router/facade_routes.py`
- API contract: `openapi/openclaw.json`
- GET, reflect, dry-run extract, and dry-run refresh use recall quotas. Other writes use retain quotas.
- JSON body limit: `MEMORY_ROUTER_MAX_BODY_BYTES` (default: 1 MiB).
- Retain, recall, and dry-run extract enforce their item/content/query limits. Other writes rely on the JSON limit and Hindsight validation.
- Facade responses: 256 KiB, four process scans, 8,192 fields, 30 seconds.
- Request scans run inline with a five-second deadline. Bodies are bounded by the configured JSON limit (default: 1 MiB); query scans inspect at most 256 pairs.
- Query values use instruction rules but intentionally skip encoded-payload/Base64 heuristics. Route semantics and Hindsight validation bound their use, including write-capable query routes.
- Response worker/capacity/limit failure: `503 facade_scan_unavailable`, `Retry-After: 1`; no quarantine.
- Unknown query parameters are dropped and excluded from security evidence.

Webhooks, file transfer, import/export, metrics, provider-credential LLM health probes, cross-writer listings, and deprecated upstream routes are denied and quarantined.

## Failure mapping

`HINDSIGHT_TIMEOUT_MS` must be positive.

| Hindsight result | Router response |
| --- | --- |
| Timeout | `504 hindsight_timeout` |
| Facade 4xx except 401/403 | Same status, sanitized `hindsight_http_error` |
| Facade response over 256 KiB | `502 hindsight_response_too_large` |
| Unsafe facade response | `502 hindsight_unsafe_response` |
| Facade scanner worker failure, busy capacity, or field/time limit | `503 facade_scan_unavailable` |
| Redirect, 401/403, 5xx, network, or malformed response | Typed 502 |

Upstream response bodies are never returned.

A typed recall failure affects only the Hindsight read bank that failed. If all configured read banks fail, recall returns empty results. Unexpected application/database failures still propagate rather than being hidden as Hindsight degradation.

## Consumption limits

Retain and recall have separate per-writer and global sliding-window budgets. Request bounds return `413`; quota exhaustion returns `429 hindsight_rate_limited` with `Retry-After`.

PostgreSQL-backed limits are shared across router replicas. Authenticated requests consume quota before content scanning, so blocked/quarantined scans, upstream failures, and response-scan failures count. Unknown writers and cheap structural failures do not.

A generic memory-provider abstraction or support for additional memory systems is not implemented in this repository yet.
