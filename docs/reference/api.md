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

The Hindsight facade surface (bank management, memories, documents, entities, mental models, directives, observations, operations, knowledge base, and bank observability) is documented in `openapi/openclaw.json`. Every facade endpoint resolves `{bank_id}` as a writer ID, enforces router authentication, safety scanning, and retain/recall quotas, and forwards to the writer's resolved Hindsight bank. Deliberately denied surfaces: webhooks, file upload and document transfer/import/export, `/metrics`, cross-writer listings (`GET /v1/default/banks`, `/v1/default/chunks/{id}`, `/v1/default/files/download/{key}`, `/v1/bank-template-schema`), and upstream-deprecated endpoints.

Facade proxying notes: write bodies are bounded by the global request-body limit, not retain content bounds. Upstream non-2xx statuses pass through with their original status code and a sanitized `hindsight_http_error` body; an empty upstream 2xx body is forwarded as `200 null`.

Quarantine administration is exposed under `/admin/quarantine/*` with separate read, review, and cleanup scopes. See [authentication](../security/authentication.md) and the OpenAPI document for request/response schemas.

Stable router errors are returned for policy rejection, request bounds, rate limiting, storage/capacity failures, and mapped Hindsight failures. Upstream Hindsight response bodies are not exposed.
