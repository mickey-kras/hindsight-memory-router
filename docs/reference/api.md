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
| `/auth/human/sign-out` | No body; human bearer Authorization header | `signed_out: true` |

`expires_at` is an integer UNIX timestamp in seconds. Grants are `{bank, scopes}`
objects. These endpoints return `404` when disabled; malformed requests return
`400`/`413`, authentication failures `401`, exhausted limits `429`, and unavailable
identity/shared storage or inactive policy `503`. All responses are `no-store`.
Only start and exchange permit unauthenticated requests. See the
[protocol and client requirements](../security/authentication.md#optional-human-login-protocol-contract).

With `MEMORY_ROUTER_PRINCIPALS` set, `{writer}` path segments are target banks
and each request is authorized against the principal's per-bank grants (see
[authentication](../security/authentication.md)); `GET /v1/default/banks`
returns only banks where the principal holds the `bank.list` scope.
PostgreSQL-backed principal limit failures return `503 principal_rate_unavailable`
or `503 principal_concurrency_unavailable` with `Retry-After: 1`.
Request scan saturation, worker failure, hard timeout, or shutdown returns
`503 request_scan_unavailable` with `Retry-After: 1`, including retain approval.
Native recall-result and supplemental scan failures return `503 recall_scan_unavailable`;
no partial recall content is returned. All safety scans share four worker slots.
Operational scanner failures do not forward or quarantine the request.

`/health/live` is anonymous liveness with a static `{"status": "alive"}` body. `/health/ready` is readiness; `/health` is its alias; `/ready` is deprecated. Readiness answers anonymous callers with only `{"status": ...}`; the full upstream payload requires router authentication. `/version` requires router authentication. Other router endpoints require authentication unless development-only anonymous access is enabled. Responses authenticated by the legacy `MEMORY_ROUTER_TOKEN` or `MEMORY_ROUTER_ADMIN_TOKEN` carry a `Deprecation` header; both credentials are removed at the next major release.

With `MEMORY_ROUTER_METRICS_ENABLED=true`, `GET /metrics` returns router counters in Prometheus text format: authentication failures, HTTP 429 and quarantine 507 rejections by route class, failed or degraded recall bank calls, sweeper failures, and a `review_side_effect_started` gauge refreshed at scrape time. It requires the admin read scope (read, review, or legacy token; in principal mode, a principal holding any `quarantine.review` grant), shares the admin read rate limit, and is off by default.

Facade contract: `openapi/openclaw.json`.

- Principal mode (`MEMORY_ROUTER_PRINCIPALS`): `{bank_id}` is the literal target bank; the bearer token must grant the requested operation on that bank. Missing grants return `403 authorization_denied`.
- Legacy shared-token mode (`MEMORY_ROUTER_TOKEN`): `{bank_id}` is a writer ID resolved to its configured write bank.
- Every route uses router authentication, safety scanning, and a retain or recall quota. Development-only anonymous mode also applies.
- Writes use the global JSON limit; retain has stricter limits.
- Response scanner worker, capacity, field, or time failure returns `503 facade_scan_unavailable` with `Retry-After: 1`.
- An empty upstream success body returns JSON `null` only when the route permits it. Otherwise validation returns a typed 502.
- Failure mapping: [Hindsight upstream](../providers/hindsight.md#failure-mapping).

Denied: webhooks, file upload/transfer, import/export, upstream `/metrics`, provider-credential probes (`POST /v1/default/banks/{bank_id}/health/llm`), deprecated upstream routes, and cross-writer endpoints (`/v1/default/chunks/{id}`, `/v1/default/files/download/{key}`, `/v1/bank-template-schema`). `GET /v1/default/banks` is denied in legacy token mode and filtered by the `bank.list` grant in principal mode.

Quarantine administration is exposed under `/admin/quarantine/*` with separate read, review, and cleanup scopes. See [authentication](../security/authentication.md) and the OpenAPI document for request/response schemas.

Stable router errors are returned for policy rejection, request bounds, rate limiting, storage/capacity failures, and mapped Hindsight failures. Upstream Hindsight error response bodies are not exposed.

Native retain returns the configured Hindsight acknowledgment object only after bounded safety scanning. Sync/async flags, operation IDs, usage, and safe additive fields are preserved. Invalid shape, unsafe content, or unavailable response scanning returns a sanitized `502`; the write may already have completed, so verify status before retrying. These post-write failures have no `Retry-After` and do not queue a replay.
