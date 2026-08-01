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

The UI mounts the committed specification read-only and disables submit methods. It is intended for browsing schemas, authentication requirements, and response contracts—not for sending router or admin requests. No API keys are supplied to the Swagger container.

Stop it with:

```bash
docker compose \
  -f docs/docker-compose.swagger.yml \
  --profile docs \
  down
```

## Authentication model

The contract defines two bearer schemes:

- `RouterToken` for `/version` and normal retain/recall operations.
- `AdminToken` for all `/admin/quarantine/*` operations.

`GET /health` is anonymous.

The admin token is for manual review clients only and must not be exposed to agents.

## Contract maintenance

When the HTTP surface changes:

1. Update `openapi/openapi.json` in the same pull request.
2. Update the route/auth contract test.
3. Run `npm run openapi:lint` and `npm test`.

CI fails when documented paths, methods, authentication schemes, or the API version drift from the implementation.
