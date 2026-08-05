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
GET  /admin/quarantine/queue                    read or review token
GET  /admin/quarantine/stats                    read or review token
POST /admin/quarantine/cleanup                  cleanup token
GET  /admin/quarantine/items/{id}               read or review token
POST /admin/quarantine/items/{id}/approve       review token
POST /admin/quarantine/items/{id}/reject        review token
POST /admin/quarantine/items/{id}/postpone      review token
```

The legacy `MEMORY_ROUTER_ADMIN_TOKEN` remains a migration superuser for every admin route. Prefer scoped tokens and leave the legacy token unset. Router and admin authentication fail closed when no token authorized for the requested capability is configured. `MEMORY_ROUTER_ALLOW_ANONYMOUS=true` enables anonymous router access for local development only.

## Images

GHCR is canonical; Docker Hub is a mirror.

```text
ghcr.io/mickey-kras/hindsight-memory-router:<git-sha>
ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest>
docker.io/mickeykrasilnikov/hindsight-memory-router:<git-sha>
docker.io/mickeykrasilnikov/hindsight-memory-router@sha256:<digest>
```

Pin deployments by digest:

```yaml
services:
  memory-router:
    image: ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest>
```

`latest` remains available for convenience but is mutable. The publish workflow records both registry digests in the job summary and an `image-digests-<commit>` artifact.

Record the running digest after deployment:

```bash
docker inspect --format='{{index .RepoDigests 0}}' <container>
```

Verify a pinned GHCR image:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/mickey-kras/hindsight-memory-router/.github/workflows/publish.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest>
```

The container runs as the non-root `node` user.

## Configuration

```text
MEMORY_ROUTER_PORT=8890
MEMORY_ROUTER_TOKEN=change-me
MEMORY_ROUTER_ADMIN_READ_TOKEN=change-me-admin-read
MEMORY_ROUTER_ADMIN_REVIEW_TOKEN=change-me-admin-review
MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN=change-me-admin-cleanup
MEMORY_ROUTER_ADMIN_TOKEN=
MEMORY_ROUTER_ALLOW_ANONYMOUS=false
MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX=120
MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX=30
MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS=60000
MEMORY_ROUTER_MAX_BODY_BYTES=1048576
MEMORY_ROUTER_REGISTRY=/app/writer_registry.example.json

HINDSIGHT_BASE_URL=http://hindsight:8888
HINDSIGHT_API_KEY=change-me
HINDSIGHT_TIMEOUT_MS=10000

QUARANTINE_PUBLIC_KEY=<PEM or base64 PEM>
QUARANTINE_DATABASE_URL=sqlite:./data/quarantine.db
QUARANTINE_MAX_POSTPONES=3
QUARANTINE_MAX_ITEM_BYTES=1048576
QUARANTINE_MAX_PENDING_ITEMS=1000
QUARANTINE_MAX_PENDING_ITEMS_PER_WRITER=50
QUARANTINE_MAX_ENCRYPTED_BYTES=104857600
QUARANTINE_RATE_LIMIT_MAX=30
QUARANTINE_RATE_LIMIT_GLOBAL_MAX=300
QUARANTINE_DISTINCT_FAMILY_LIMIT_MAX=10
QUARANTINE_REQUARANTINE_OPS_MAX=1000
QUARANTINE_RATE_LIMIT_WINDOW_MS=60000
QUARANTINE_ITEM_TTL_DAYS=30
QUARANTINE_SWEEP_INTERVAL_SECONDS=3600
QUARANTINE_EVENT_RETENTION_DAYS=90
```

Supported database URLs:

```text
sqlite:/absolute/path/quarantine.db
sqlite:relative/path/quarantine.db
postgresql://user:password@database:5432/quarantine
```

Use a separate PostgreSQL database or schema from Hindsight application data.

`HINDSIGHT_TIMEOUT_MS` must be a positive integer. Hindsight timeouts return `504 hindsight_timeout`; HTTP, network, and invalid JSON responses return a typed `502` error. Upstream error bodies are truncated.

Breaking change: the built-in default database URL is now `sqlite:./data/quarantine.db` (resolved against the router working directory). It previously defaulted to the host-specific path `sqlite:/volume1/reports/hindsight-quarantine/quarantine.db`. Deployments that relied on the old default must set `QUARANTINE_DATABASE_URL` explicitly (or move the existing database to `./data/quarantine.db`) before upgrading.

At startup the configured router validates quarantine storage and fails fast with a clear error when it is unreachable or not writable (SQLite database file and directory permissions, PostgreSQL connectivity and schema privileges), instead of failing on the first quarantined write. Embedded deployments that construct the server programmatically can opt out with `validateStorage: false`.

`QUARANTINE_PUBLIC_KEY` is validated when the router starts. Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY` causes configured router startup to fail. Keep the private key outside the router runtime and supply it only to an authorized local review or migration client.

## Authentication

- Router and admin tokens are separate.
- `MEMORY_ROUTER_ADMIN_READ_TOKEN` can list queue state, read statistics, and fetch encrypted items only.
- `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN` has read access plus approve, reject, and postpone actions.
- `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN` can invoke cleanup only; it cannot list or review items.
- `MEMORY_ROUTER_ADMIN_TOKEN` is a legacy migration superuser and should be unset after clients move to scoped tokens.
- Token comparison is constant-time.
- Token values are never logged or stored in quarantine.
- Failed authentication creates one deduplicated `auth_failed` item per route group.
- Admin reads and writes have separate process-local sliding-window limits.
- Failed authentication does not consume admin quota.

A leaked read token cannot mutate quarantine state. A leaked cleanup token cannot inspect encrypted envelopes or make review decisions. A leaked review token can read encrypted envelopes and run review actions, but cannot execute bulk cleanup. No admin token can decrypt envelopes or approve modified content.

Token migration and rotation:

1. Generate independent read, review, and cleanup tokens.
2. Configure the scoped tokens while temporarily retaining the legacy admin token, then restart the router.
3. Update each admin client to use only the token matching its responsibilities.
4. Verify every scoped client works and confirm the startup warning still reports the legacy migration superuser as active.
5. Unset `MEMORY_ROUTER_ADMIN_TOKEN` and restart the router again.
6. Rotate any individual scoped token without changing the others.
7. Review quarantine events if compromise is suspected.

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

Recall availability rules:

- A typed Hindsight failure affects only that read bank.
- If all read banks fail, recall returns empty results.
- `429`, `507`, and `quarantine_request_in_review` prevent the affected suspicious result from being returned but do not fail recall.
- Unexpected application or database errors still propagate.
- Degradation logs contain structured error codes, not upstream response text.
- Retain never degrades when quarantine is unavailable.

There is no Hindsight quarantine bank.

## Quarantine

`quarantine_items` stores current encrypted state. `quarantine_events` stores audit history. Existing databases are migrated in place. Legacy rows keep `NULL` dedupe and expiry values, so they are neither merged nor expired automatically.

```text
payload -> canonical SHA-256 -> AES-256-GCM envelope -> SQLite/PostgreSQL
```

The router stores only the public key. Any `QUARANTINE_PRIVATE_KEY*` environment variable makes startup fail.

### Deduplication

Identical retain and recall quarantine requests reuse one pending item. The dedupe key covers request kind, writer, policy target, and canonical JSON payload. Object key order and JSON formatting do not matter; string content remains exact. A repeat refreshes the item, increments `requarantine_count`, and records `requarantined`. Repeats are rejected with `409` while the matching item is under review. Security-event identities are normalized by method and path, scoped by writer, and capped across the process.

### Retention

Pending and postponed items expire after `QUARANTINE_ITEM_TTL_DAYS`; `0` disables expiry. The sweeper runs every `QUARANTINE_SWEEP_INTERVAL_SECONDS`; `0` disables it. Expired items stop counting toward capacity immediately and are later removed with a `cleanup` event.

Events older than `QUARANTINE_EVENT_RETENTION_DAYS` are pruned in batches of 1000; `0` keeps them forever. Pruning is destructive and independent of item expiry, so export events first when long-term audit history is required.

Limits fail closed:

- `413`: item too large;
- `429`: rate limit exceeded;
- `507`: quarantine capacity exhausted.

PostgreSQL rate limits are shared across router replicas and use PostgreSQL time. SQLite and in-memory limits are process-local.

## Manual review

1. List pending items with the review token.
2. Fetch the encrypted item with the review token.
3. Decrypt outside the router:

```bash
npm run build
private-key-command | node dist/src/cli/decryptQuarantine.js encrypted-response.json
```

4. Approve, reject, or postpone with the review token.

Approval requires the complete decrypted object unchanged. Modified content returns `quarantine_hash_mismatch`.

Review actions claim the item in a short transaction, call Hindsight without holding a database lock, then finalize in a second transaction. Concurrent review changes return `409 quarantine_review_changed`.

A failed Hindsight call restores the previous review state and records `review_interrupted`. For timeout or network errors, verify Hindsight state before retrying because the upstream action may have completed before the response failed.

On startup, stale `review_in_progress` items are moved to `postponed` without increasing the postpone count. A crash after Hindsight applied an action cannot be rolled back; inspect Hindsight before re-approving.

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

Use the cleanup token for preview and execution.

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
