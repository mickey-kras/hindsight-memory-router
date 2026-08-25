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
- Retain and recall also enforce content/query limits. Other writes rely on the JSON limit and Hindsight validation.
- Response scan: four concurrent jobs, 8,192 fields, 30 seconds.
- Scan capacity/limit failure: `503 facade_scan_unavailable`; no quarantine.
- Unknown query parameters are dropped and excluded from security evidence.

Webhooks, file transfer, import/export, metrics, cross-writer listings, and deprecated upstream routes are denied and quarantined.

## Failure mapping

`HINDSIGHT_TIMEOUT_MS` must be positive.

| Hindsight result | Router response |
| --- | --- |
| Timeout | `504 hindsight_timeout` |
| Facade 4xx except 401/403 | Same status, sanitized `hindsight_http_error` |
| Redirect, 401/403, 5xx, network, or malformed response | Typed 502 |

Upstream response bodies are never returned.

A typed recall failure affects only the Hindsight read bank that failed. If all configured read banks fail, recall returns empty results. Unexpected application/database failures still propagate rather than being hidden as Hindsight degradation.

## Consumption limits

Retain and recall have separate per-writer and global sliding-window budgets. Request bounds return `413`; quota exhaustion returns `429 hindsight_rate_limited` with `Retry-After`.

PostgreSQL-backed limits are shared across router replicas. These normal Hindsight limits are independent of quarantine capacity/rate limits and admin throttling. Requests that are quarantined or blocked before reaching Hindsight do not consume the normal Hindsight budget.

A generic memory-provider abstraction or support for additional memory systems is not implemented in this repository yet.
