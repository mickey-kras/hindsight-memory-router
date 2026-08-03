# hindsight-memory-router

[![ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![codeql](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Policy router between OpenClaw and Hindsight.

```text
OpenClaw -> memory-router -> Hindsight
```

The router selects memory banks, filters recall, and sends unknown or suspicious material to encrypted quarantine.

## API

```text
GET  /health                                      anonymous
GET  /ready                                       anonymous
GET  /version                                     router token
POST /v1/default/banks/{writer}/memories          router token
POST /v1/default/banks/{writer}/memories/recall   router token
```

Admin API:

```text
GET  /admin/quarantine/queue
GET  /admin/quarantine/stats
POST /admin/quarantine/cleanup
GET  /admin/quarantine/items/{id}
POST /admin/quarantine/items/{id}/approve
POST /admin/quarantine/items/{id}/reject
POST /admin/quarantine/items/{id}/postpone
```

Router and admin authentication fail closed when their token is unset. `MEMORY_ROUTER_ALLOW_ANONYMOUS=true` enables anonymous router access for local development only.

## Images

```text
ghcr.io/mickey-kras/hindsight-memory-router:<git-sha>
docker.io/mickeykrasilnikov/hindsight-memory-router:<git-sha>
```

The container runs as the non-root `node` user.

## Configuration

```text
MEMORY_ROUTER_PORT=8890
MEMORY_ROUTER_TOKEN=change-me
MEMORY_ROUTER_ADMIN_TOKEN=change-me-admin
MEMORY_ROUTER_ALLOW_ANONYMOUS=false
MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX=120
MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX=30
MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS=60000
MEMORY_ROUTER_MAX_BODY_BYTES=1048576
MEMORY_ROUTER_REGISTRY=/app/writer_registry.example.json

HINDSIGHT_BASE_URL=http://hindsight:8888
HINDSIGHT_API_KEY=change-me

QUARANTINE_PUBLIC_KEY=<PEM or base64 PEM>
QUARANTINE_DATABASE_URL=sqlite:/volume1/reports/hindsight-quarantine/quarantine.db
QUARANTINE_MAX_POSTPONES=3
QUARANTINE_MAX_ITEM_BYTES=1048576
QUARANTINE_MAX_PENDING_ITEMS=1000
QUARANTINE_MAX_ENCRYPTED_BYTES=104857600
QUARANTINE_RATE_LIMIT_MAX=30
QUARANTINE_RATE_LIMIT_GLOBAL_MAX=300
QUARANTINE_REQUARANTINE_OPS_MAX=1000
QUARANTINE_RATE_LIMIT_WINDOW_MS=60000
```

Supported database URLs:

```text
sqlite:/absolute/path/quarantine.db
sqlite:relative/path/quarantine.db
postgresql://user:password@database:5432/quarantine
```

Use a separate PostgreSQL database or schema from Hindsight application data.

## Authentication

- Router and admin tokens are separate.
- Token comparison is constant-time.
- Token values are never logged or stored in quarantine.
- Failed authentication creates one deduplicated `auth_failed` item per route group.
- Admin reads and writes have separate process-local sliding-window limits.
- Failed authentication does not consume admin quota.

A leaked admin token can read encrypted envelopes and run review actions. It cannot decrypt envelopes or approve modified content.

Token rotation:

1. Generate new router and admin tokens.
2. Update the deployment and restart the router.
3. Update OpenClaw and admin clients.
4. Review quarantine events if compromise is suspected.

Keep tokens out of prompts, logs, shell history, and committed configuration.

## OpenClaw

```text
hindsightApiUrl = http://memory-router:8890
hindsightApiToken = MEMORY_ROUTER_TOKEN
dynamicBankId = false
bankId = <writer_id>
bankIdPrefix = unset
autoRecall = true
autoRetain = true
enableKnowledgeTools = false initially
```

## Policy behavior

Retain:

```text
known writer + clean content -> assigned Hindsight bank
unknown writer               -> encrypted quarantine
suspicious content           -> encrypted quarantine
```

Recall:

```text
known writer                 -> allowed read banks only
unknown writer               -> empty results + quarantine item
suspicious query             -> empty results + quarantine item
suspicious recalled result   -> suppressed + quarantine item
reviewed allowed result      -> returned while content is unchanged
reviewed blocked result      -> suppressed and invalidated
```

There is no Hindsight quarantine bank.

## Quarantine

`quarantine_items` stores current encrypted state. `quarantine_events` stores audit history.

```text
payload -> canonical SHA-256 -> AES-256-GCM envelope -> SQLite/PostgreSQL
```

The router stores only the public key. Any `QUARANTINE_PRIVATE_KEY*` environment variable makes startup fail.

Limits fail closed:

- `413`: item too large;
- `429`: rate limit exceeded;
- `507`: quarantine capacity exhausted.

PostgreSQL rate limits are shared across router replicas and use PostgreSQL time. SQLite and in-memory limits are process-local.

## Manual review

1. List pending items with the admin token.
2. Fetch the encrypted item.
3. Decrypt outside the router:

```bash
npm run build
private-key-command | node dist/src/cli/decryptQuarantine.js encrypted-response.json
```

4. Approve, reject, or postpone.

Approval requires the complete decrypted object unchanged. Modified content returns `quarantine_hash_mismatch`.

## Legacy migration

```bash
npm run build
private-key-command | npm run migrate:legacy-quarantine -- \
  --queue /path/to/review.jsonl \
  --objects /path/to/quarantine-objects \
  --database sqlite:/path/to/quarantine.db
```

The command is idempotent and leaves source files untouched. Verify the migration summary before removing legacy data.

## Cleanup

Preview:

```json
{
  "scope": "pending",
  "reasons": ["unknown_writer"],
  "older_than": "2026-07-01T00:00:00Z",
  "dry_run": true
}
```

Execute with the returned count:

```json
{
  "scope": "pending",
  "reasons": ["unknown_writer"],
  "older_than": "2026-07-01T00:00:00Z",
  "dry_run": false,
  "expected_count": 42
}
```

Cleanup returns `409` if the selection changed after preview.

## Checks

```bash
npm run format:check
npm run lint
npm run openapi:lint
npm run test:coverage
npm run typecheck
npm run security:audit
npm run aislop:ci
```

## License

MIT
