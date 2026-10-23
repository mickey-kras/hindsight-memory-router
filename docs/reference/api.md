# API reference

[Documentation](../README.md) | [Repository](../../README.md)

The canonical machine-readable API is `openapi/openapi.json`.

Core endpoints:

```text
GET  /health/live
GET  /health/ready
GET  /health
GET  /ready                 (deprecated)
GET  /version
GET  /v1/default/banks      (principal mode only)
POST /v1/default/banks/{writer}/memories
POST /v1/default/banks/{writer}/memories/recall
```

Optional human authentication (`MEMORY_ROUTER_HUMAN_AUTH`):

| POST endpoint | JSON request | Success response |
| --- | --- | --- |
| `/auth/human/start` | `redirect_uri`, `state`, `code_challenge` | `transaction_id`, `authorization_url` |
| `/auth/human/exchange` | `transaction_id`, `code`, `state`, `code_verifier` | `token`, `token_type: "Bearer"`, `principal_id`, `grants`, `expires_at` |
| `/auth/human/sign-out` | No body. The `Authorization` header holds the human bearer token | `signed_out: true` |

`expires_at` is an integer UNIX timestamp in seconds.
Grants are `{bank, scopes}` objects.
These endpoints return `404` when disabled.
Malformed requests return `400`/`413`, authentication failures return `401`, and exhausted limits return `429`.
Unavailable identity or shared storage, or an inactive policy, returns `503`.
All responses are `no-store`.

Only start and exchange accept unauthenticated requests.
See the [protocol and client requirements](../security/authentication.md#optional-human-login-protocol-contract).

With `MEMORY_ROUTER_PRINCIPALS` set, `{writer}` path segments are target banks.
Each request must have the grants of the principal for that bank. See [authentication](../security/authentication.md).
`GET /v1/default/banks` returns only banks where the principal holds `bank.list`.
PostgreSQL-backed principal limit failures return `503 principal_rate_unavailable` or `503 principal_concurrency_unavailable` with `Retry-After: 1`.

Request scan saturation, worker failure, hard timeout, or shutdown returns `503 request_scan_unavailable` with `Retry-After: 1`.
This includes retain approval.
Native recall-result and supplemental scan failures return `503 recall_scan_unavailable`.
The response contains no partial recall content.
All safety scans share four worker slots.
Operational scanner failures do not forward or quarantine the request.

`/health/live` gives anonymous liveness with a static `{"status": "alive"}` body.
`/health/ready` gives readiness.
`/health` is its alias.
Do not use `/ready`. It is a deprecated alias.

Readiness answers anonymous callers with only `{"status": ...}`.
The full upstream payload is available only with router authentication.

`/version` is available only with router authentication.
Other router endpoints must have authentication, unless the development-only anonymous access is on.
Responses authenticated by legacy `MEMORY_ROUTER_TOKEN` or `MEMORY_ROUTER_ADMIN_TOKEN` carry a `Deprecation` header.
The next major release removes both credentials.

With `MEMORY_ROUTER_METRICS_ENABLED=true`, `GET /metrics` returns router counters in Prometheus text format.
Counters include authentication failures, HTTP 429, and quarantine 507 rejections by route class.
They also include failed or degraded recall bank calls and sweeper failures.
The response includes a `review_side_effect_started` gauge refreshed at scrape time.

The endpoint must have admin read scope: a read, review, or legacy token.
In principal mode, a principal with any `quarantine.review` grant also has access.
The endpoint shares the admin read rate limit.
It is off by default.

Facade contract: `openapi/openclaw.json`.

- Principal mode (`MEMORY_ROUTER_PRINCIPALS`): `{bank_id}` is the literal target bank. The bearer token must grant the requested operation on that bank. Missing grants return `403 authorization_denied`.
- Legacy shared-token mode (`MEMORY_ROUTER_TOKEN`): `{bank_id}` is a writer ID resolved to its configured write bank.
- Every route uses router authentication, safety scanning, and a retain or recall quota. Development-only anonymous mode also applies.
- Writes use the global JSON limit. Retain has stricter limits.
- Read-response scanner worker, capacity, field, or time failure returns `503 facade_scan_unavailable` with `Retry-After: 1`. After a successful upstream facade write, the same failure returns `502 hindsight_response_scan_unavailable` without `Retry-After`. Examine the write status before a retry. The router queues no replay.
- If the upstream sends an empty body with success, the router gives `null` only when the route permits it. Otherwise validation returns a typed 502.
- Failure mapping: [Hindsight upstream](../providers/hindsight.md#failure-mapping).

The router denies these routes: webhooks, file upload and transfer, import, export, upstream `/metrics`, provider-credential probes (`POST /v1/default/banks/{bank_id}/health/llm`), deprecated upstream routes, and cross-writer endpoints (`/v1/default/chunks/{id}`, `/v1/default/files/download/{key}`, `/v1/bank-template-schema`). In legacy token mode, the router denies `GET /v1/default/banks`. In principal mode, the `bank.list` grant filters its result.

Quarantine administration is available under `/admin/quarantine/*`, with separate read, review, and cleanup scopes. See [authentication](../security/authentication.md) and the OpenAPI document for the request and response schemas.

The router returns stable errors for policy rejection, request bounds, rate limits, storage or capacity failures, and mapped Hindsight failures. It does not show the bodies of upstream Hindsight error responses.

Native retain returns the configured Hindsight acknowledgment object only after bounded safety scanning.
The response keeps the sync and async flags, operation IDs, usage, and safe additive fields.
Invalid shape, unsafe content, or unavailable response scanning returns a sanitized `502`.
The write can already be complete.
Examine the status of the write before you retry.
These post-write failures have no `Retry-After` and do not queue replay.

