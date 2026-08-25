# API reference

The canonical machine-readable API is `openapi/openapi.json`.

Core endpoints:

```text
GET  /health/live
GET  /health/ready
GET  /health
GET  /ready                 (deprecated)
GET  /version
POST /v1/default/banks/{writer}/memories
POST /v1/default/banks/{writer}/memories/recall
```

All health endpoints are unauthenticated. `/health/live` is router-only liveness. `/health/ready` is the canonical readiness probe; `/health` is an exact readiness alias and `/ready` is deprecated. `/version`, retain, and recall use router authentication unless development-only anonymous access is explicitly enabled.

Facade contract: `openapi/openclaw.json`.

- `{bank_id}` is a writer ID. The router resolves the Hindsight bank.
- Every route requires router authentication, safety scanning, and a retain or recall quota.
- Write bodies use the global JSON limit. Retain has stricter content limits.
- Empty upstream success bodies keep the route status and return JSON `null`.
- Failure mapping: [Hindsight upstream](../providers/hindsight.md#failure-mapping).

Denied: webhooks, file upload/transfer, import/export, `/metrics`, deprecated upstream routes, and cross-writer endpoints (`GET /v1/default/banks`, `/v1/default/chunks/{id}`, `/v1/default/files/download/{key}`, `/v1/bank-template-schema`).

Quarantine administration is exposed under `/admin/quarantine/*` with separate read, review, and cleanup scopes. See [authentication](../security/authentication.md) and the OpenAPI document for request/response schemas.

Stable router errors are returned for policy rejection, request bounds, rate limiting, storage/capacity failures, and mapped Hindsight failures. Upstream Hindsight response bodies are not exposed.
