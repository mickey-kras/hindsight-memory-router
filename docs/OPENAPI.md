# OpenAPI and Swagger UI

[Documentation](README.md) | [Repository](../README.md)

The committed API contract is `openapi/openapi.json` and uses OpenAPI 3.1.

Validate it locally:

```bash
npm ci
npm run openapi:lint
```

## Browse with Swagger UI

Swagger UI is an opt-in documentation service. The production router image does not include it. It is not available until you start it explicitly.

```bash
docker compose \
  -f docs/docker-compose.swagger.yml \
  --profile docs \
  up
```

Open `http://127.0.0.1:8080`.

The UI image has a version tag and an examined manifest digest pin.
The service mounts the committed specification read-only and disables submit methods.
Use it to browse schemas, authentication requirements, and response contracts.
It cannot send router or admin requests.
The Swagger container gets no API keys.

Stop it with:

```bash
docker compose \
  -f docs/docker-compose.swagger.yml \
  --profile docs \
  down
```

## Authentication model

The contracts define four bearer mechanisms:

- `RouterToken` for `/version` and normal retain and recall operations.
- `AdminToken` for `/admin/quarantine/*` operations.
- `PrincipalToken` for configured application principals and their granted operations.
- `HumanToken` for short-lived interactive sessions and their granted bank read, retain, recall, and reflect operations. Human sessions cannot administer banks, write bank configuration, or access quarantine administration or metrics.

`AdminToken` is a generic OpenAPI bearer slot. The credential accepted by a concrete operation is capability-scoped:

- Queue, statistics, and encrypted-item reads accept the read or review token.
- Approve, reject, and postpone accept the review token.
- Cleanup accepts the cleanup token.
- All admin endpoints accept the legacy admin token, but only during migration.

`GET /health/live`, `GET /health`, `GET /health/ready`, and deprecated `GET /ready` accept anonymous requests. Readiness responses expose full upstream details only to an authenticated router, application, or human principal (or when anonymous access is on).

Use admin credentials only for human-operated or tightly controlled service clients.
Do not expose these credentials to agents.
Configure scoped credentials.
Migrate clients.
Leave `MEMORY_ROUTER_ADMIN_TOKEN` unset after migration.

## Contract maintenance

When the HTTP surface changes:

1. Update `openapi/openapi.json` and, for facade operations, `openapi/openclaw.json` in the same pull request.
2. Update the route and auth contract tests.
3. Run `npm run openapi:lint`. Run `python -m pytest`.

CI fails when documented paths, methods, authentication schemes, request constraints, malformed-request status codes, or the API version drift from the implementation.

