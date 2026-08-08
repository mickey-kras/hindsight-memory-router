# API reference

The canonical machine-readable API is `openapi/openapi.json`.

Core endpoints:

```text
GET  /health
GET  /ready
GET  /version
POST /v1/default/banks/{writer}/memories
POST /v1/default/banks/{writer}/memories/recall
```

`/health` and `/ready` are unauthenticated probes. `/version`, retain, and recall use router authentication unless development-only anonymous access is explicitly enabled.

Quarantine administration is exposed under `/admin/quarantine/*` with separate read, review, and cleanup scopes. See [authentication](../security/authentication.md) and the OpenAPI document for request/response schemas.

Stable router errors are returned for policy rejection, request bounds, rate limiting, storage/capacity failures, and mapped Hindsight failures. Upstream Hindsight response bodies are not exposed.
