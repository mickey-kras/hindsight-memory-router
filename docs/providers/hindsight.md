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

Memory Router maps writer policy to Hindsight banks and enforces separate retain/recall request bounds and quotas before Hindsight calls.

## Failure mapping

`HINDSIGHT_TIMEOUT_MS` must be a positive integer. Hindsight timeouts return `504 hindsight_timeout`; HTTP, network, malformed-response, and response-stream failures return typed `502` errors. Upstream response bodies are never exposed; diagnostics remain bounded and fixed-field.

A typed recall failure affects only the Hindsight read bank that failed. If all configured read banks fail, recall returns empty results. Unexpected application/database failures still propagate rather than being hidden as Hindsight degradation.

## Consumption limits

Retain and recall have separate per-writer and global sliding-window budgets. Request bounds return `413`; quota exhaustion returns `429 hindsight_rate_limited` with `Retry-After`.

PostgreSQL-backed limits are shared across router replicas. These normal Hindsight limits are independent of quarantine capacity/rate limits and admin throttling. Requests that are quarantined or blocked before reaching Hindsight do not consume the normal Hindsight budget.

A generic memory-provider abstraction or support for additional memory systems is not implemented in this repository yet.
