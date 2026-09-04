# API reference

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

With `MEMORY_ROUTER_PRINCIPALS` set, `{writer}` path segments are target banks
and each request is authorized against the principal's per-bank grants (see
[authentication](../security/authentication.md)); `GET /v1/default/banks`
returns only banks where the principal holds the `bank.list` scope.
PostgreSQL-backed principal limit failures return `503 principal_rate_unavailable`
or `503 principal_concurrency_unavailable` with `Retry-After: 1`.

Health and `/version` are unauthenticated. `/health/live` is liveness. `/health/ready` is readiness; `/health` is its alias. `/ready` is deprecated. Other router endpoints require authentication unless development-only anonymous access is enabled.

Facade contract: `openapi/openclaw.json`.

- `{bank_id}` is a writer ID. The router resolves the Hindsight bank.
- Every route uses router authentication, safety scanning, and a retain or recall quota. Development-only anonymous mode also applies.
- Writes use the global JSON limit; retain has stricter limits.
- Scanner worker, capacity, field, or time failure returns `503 facade_scan_unavailable` with `Retry-After: 1`.
- An empty upstream success body returns JSON `null` only when the route permits it. Otherwise validation returns a typed 502.
- Failure mapping: [Hindsight upstream](../providers/hindsight.md#failure-mapping).

Denied: webhooks, file upload/transfer, import/export, `/metrics`, provider-credential probes (`POST /v1/default/banks/{bank_id}/health/llm`), deprecated upstream routes, and cross-writer endpoints (`/v1/default/chunks/{id}`, `/v1/default/files/download/{key}`, `/v1/bank-template-schema`). `GET /v1/default/banks` is denied in legacy token mode and filtered by the `bank.list` grant in principal mode.

Quarantine administration is exposed under `/admin/quarantine/*` with separate read, review, and cleanup scopes. See [authentication](../security/authentication.md) and the OpenAPI document for request/response schemas.

Stable router errors are returned for policy rejection, request bounds, rate limiting, storage/capacity failures, and mapped Hindsight failures. Upstream Hindsight response bodies are not exposed.
