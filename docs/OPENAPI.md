# OpenAPI and Swagger UI

The committed API contract is `openapi/openapi.json` and uses OpenAPI 3.1.

Validate it locally:

```bash
npm ci
npm run openapi:lint
```

## Browse with Swagger UI

Swagger UI is an opt-in documentation service. It is not embedded in the production router image and is not exposed unless started explicitly.

```bash
docker compose \
  -f docs/docker-compose.swagger.yml \
  --profile docs \
  up
```

Open `http://127.0.0.1:8080`.

The UI image is pinned by both version tag and verified manifest digest. The service mounts the committed specification read-only and disables submit methods. It is intended for browsing schemas, authentication requirements, and response contracts—not for sending router or admin requests. No API keys are supplied to the Swagger container.

Stop it with:

```bash
docker compose \
  -f docs/docker-compose.swagger.yml \
  --profile docs \
  down
```

## Authentication model

The contract defines bearer schemes for:

- `RouterToken` for `/version` and normal retain/recall operations.
- `AdminReadToken` for queue, statistics, and encrypted-item reads.
- `AdminReviewToken` for reads plus approve, reject, and postpone operations.
- `AdminCleanupToken` for cleanup only.
- `LegacyAdminToken` as a temporary migration superuser for every admin operation.

`GET /health` and `GET /ready` are anonymous.

Admin credentials are for human-operated or tightly controlled service clients only and must not be exposed to agents. Configure scoped credentials, migrate clients, then leave `MEMORY_ROUTER_ADMIN_TOKEN` unset.

## Contract maintenance

When the HTTP surface changes:

1. Update `openapi/openapi.json` in the same pull request.
2. Update the route/auth contract test.
3. Run `npm run openapi:lint` and `npm test`.

CI fails when documented paths, methods, authentication schemes, request constraints, malformed-request status codes, or the API version drift from the implementation.
