# hindsight-memory-router

[![ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![codeql](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml)
[![aislop ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/aislop.yml/badge.svg?branch=main)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/aislop.yml)
[![aislop score](https://badges.scanaislop.com/score/mickey-kras/hindsight-memory-router.svg)](https://scanaislop.com/mickey-kras/hindsight-memory-router)
[![docker hub](https://img.shields.io/docker/v/mickeykrasilnikov/hindsight-memory-router?label=docker%20hub)](https://hub.docker.com/r/mickeykrasilnikov/hindsight-memory-router)
[![docker pulls](https://img.shields.io/docker/pulls/mickeykrasilnikov/hindsight-memory-router)](https://hub.docker.com/r/mickeykrasilnikov/hindsight-memory-router)
[![ghcr](https://img.shields.io/badge/ghcr.io-mickey--kras%2Fhindsight--memory--router-blue)](https://github.com/mickey-kras/hindsight-memory-router/pkgs/container/hindsight-memory-router)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node >=22.13](https://img.shields.io/badge/node-%3E%3D22.13-brightgreen.svg)](https://nodejs.org)

Hindsight-compatible memory policy router for OpenClaw.

```text
OpenClaw Hindsight plugin -> memory-router -> Hindsight API
```

The router is a policy facade. Approved memory belongs in Hindsight; unapproved material belongs only in encrypted quarantine storage.

## What it does

```text
writer identity required
bank chosen by policy, not by agent
recall is ACL-filtered
unknown or suspicious material is encrypted before review
suspicious recalled memories stay blocked until reviewed
router stores only the quarantine public key
private-key decryption happens outside the router and Infosphere
unknown Hindsight endpoints are denied and recorded
```

## API

Normal facade:

```text
GET  /health                                      anonymous
GET  /ready                                       anonymous
GET  /version                                     router token
POST /v1/default/banks/{writer}/memories          router token
POST /v1/default/banks/{writer}/memories/recall   router token
```

Router authentication fails closed. When `MEMORY_ROUTER_TOKEN` is not set, retain/recall/version reject every request with `401`. The only exception is the explicit development-only opt-in `MEMORY_ROUTER_ALLOW_ANONYMOUS=true`, which restores anonymous access and prints a loud startup warning. Never enable it outside local development.

Quarantine administration:

```text
GET  /admin/quarantine/queue
GET  /admin/quarantine/stats
POST /admin/quarantine/cleanup
GET  /admin/quarantine/items/{quarantine_id}
POST /admin/quarantine/items/{quarantine_id}/approve
POST /admin/quarantine/items/{quarantine_id}/reject
POST /admin/quarantine/items/{quarantine_id}/postpone
```

Admin endpoints require `MEMORY_ROUTER_ADMIN_TOKEN` and fail closed when it is unset. The item endpoint returns metadata and the encrypted envelope; it never decrypts the payload.

Admin endpoints are throttled per router process with a sliding window: reads (`GET`) and mutations (`POST`) have separate budgets. Exceeding a budget returns `429` with `admin_rate_limited`. Failed authentication does not consume quota. Multi-instance deployments need a shared edge limit for a cluster-wide quota.

Retain and recall bodies are validated before policy execution. Structurally invalid or empty requests return `400` rather than reaching Hindsight or failing as an internal error.

All other Hindsight endpoints are denied by default. The Hindsight `bank_id` path value is treated as a router `writer_id`; policy chooses the real bank.

## Docker

Published images:

```text
docker.io/mickeykrasilnikov/hindsight-memory-router:latest
docker.io/mickeykrasilnikov/hindsight-memory-router:<git-sha>
ghcr.io/mickey-kras/hindsight-memory-router:latest
ghcr.io/mickey-kras/hindsight-memory-router:<git-sha>
```

The container runs as the non-root `node` user.

## Configuration

```text
MEMORY_ROUTER_PORT=8890
MEMORY_ROUTER_TOKEN=change-me
MEMORY_ROUTER_ADMIN_TOKEN=change-me-admin-token
MEMORY_ROUTER_ALLOW_ANONYMOUS=unset (dev-only escape hatch, see Token security)
MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX=120
MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX=30
MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS=60000
HINDSIGHT_BASE_URL=http://hindsight:8888
HINDSIGHT_API_KEY=change-me
MEMORY_ROUTER_REGISTRY=/app/writer_registry.example.json
QUARANTINE_PUBLIC_KEY=<PEM or base64 PEM>
QUARANTINE_DATABASE_URL=sqlite:/volume1/reports/hindsight-quarantine/quarantine.db
QUARANTINE_MAX_POSTPONES=3
QUARANTINE_MAX_ITEM_BYTES=1048576
QUARANTINE_MAX_PENDING_ITEMS=1000
QUARANTINE_MAX_ENCRYPTED_BYTES=104857600
QUARANTINE_RATE_LIMIT_MAX=30
QUARANTINE_RATE_LIMIT_WINDOW_MS=60000
```

`QUARANTINE_DATABASE_URL` supports:

```text
sqlite:/absolute/path/quarantine.db
sqlite:relative/path/quarantine.db
postgresql://user:password@database:5432/router
```

SQLite is the default and enables WAL mode. PostgreSQL is intended for deployments that need shared or remote quarantine state. Both backends create indexed `quarantine_items` and append-only `quarantine_events` tables. In PostgreSQL deployments, use a separate database or schema from Hindsight's application data so the security control plane is independently scoped and backed up.

`QUARANTINE_PUBLIC_KEY` is validated when the router starts. Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY` causes configured router startup to fail. Keep the private key outside the router runtime and supply it only to an authorized local review or migration client.

`QUARANTINE_MAX_POSTPONES` and the other numeric quarantine limits must be non-negative integers; malformed values fail startup. The same applies to the `MEMORY_ROUTER_ADMIN_RATE_LIMIT_*` values.

## Token security

Both bearer tokens are compared in constant time (SHA-256 pre-hashed, `crypto.timingSafeEqual`), so probing cannot learn the token length or content byte by byte.

Failed authentication is audited. Every rejected router or admin request emits a structured stderr line (`{"event":"auth_failed","route_group":"router|admin"}`) and records one deduplicated `security_event` quarantine item per route group with reason `auth_failed`, visible in the admin queue and stats. Token material is never logged or stored, and the router never logs `Authorization` headers.

Blast radius of a leaked token:

- A leaked `MEMORY_ROUTER_TOKEN` can retain and recall through the facade, subject to writer policy, content scanning, and recall ACLs. It cannot read, decrypt, approve, reject, or clean up quarantine.
- A leaked `MEMORY_ROUTER_ADMIN_TOKEN` can list queue metadata, read encrypted envelopes, and run destructive review actions (reject, postpone, cleanup). It cannot decrypt envelopes: the private key is enforced outside the router process. It cannot approve forged or altered content: approval requires the exact decrypted object whose canonical SHA-256 matches the stored digest, which only a holder of the private key can produce.

Token handling rules:

- Keep tokens out of agent configuration files, prompts, logs, and shell history. Inject them as environment variables or secrets at deploy time.
- Rotate tokens on suspicion of exposure: generate new random values, update the router environment and restart it, then update the OpenClaw plugin config (`hindsightApiToken`) and any admin clients. Old tokens stop working as soon as the router restarts. Rotate `MEMORY_ROUTER_ADMIN_TOKEN` immediately if admin queue contents or review actions may have been observed.
- After a suspected leak, review `auth_failed` and other `security_event` quarantine items and the append-only `quarantine_events` table for probing or misuse.

`MEMORY_ROUTER_ALLOW_ANONYMOUS=true` disables router authentication entirely and exists only so local development stacks can run without token plumbing. It has no effect on `/admin/*`, which always requires the admin token. Do not set it in any shared or production environment.

OpenClaw plugin config:

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

## Safety model

Retain:

```text
known writer + clean content -> assigned Hindsight write bank
unknown writer -> encrypted quarantine database row
suspicious content -> encrypted quarantine database row
```

Recall:

```text
known writer -> only allowed read banks
unknown writer -> empty results + encrypted review item
suspicious query -> empty results + encrypted review item
suspicious recalled result -> suppressed + encrypted review item
reviewed allowed result -> returned only while its evaluated text is unchanged
reviewed blocked result -> suppressed and invalidated in Hindsight
```

There is no Hindsight `quarantine` bank. Quarantine is operational security state, not searchable memory.

## Quarantine storage

`quarantine_items` holds current state and encrypted envelopes. It never stores unencrypted payloads. `quarantine_events` is append-only and retains audit events after item ciphertext is removed.

```text
raw JSON payload
    -> canonical SHA-256
    -> AES-256-GCM envelope
    -> SQLite or PostgreSQL quarantine_items
    -> no Hindsight write
```

Rate and capacity limits fail closed with `429`, `413`, or `507`; they do not silently discard data or fall back to Hindsight. The write-rate limit is global across writer IDs within each router process, so changing the URL writer does not create a fresh quota. Repeated denied requests to the same HTTP method and path refresh one current `security_event` item while appending a new audit event, preventing repeated probes from consuming one capacity slot per request.

Multi-instance deployments must add a shared edge or distributed rate limit when they need a cluster-wide quota.

## Upgrade from JSONL/file quarantine

The SQL release does not silently read the old JSONL queue or encrypted-object directory. Migrate reviewable items before deleting the legacy files:

```bash
npm run build
private-key-command | npm run migrate:legacy-quarantine -- \
  --queue /path/to/review.jsonl \
  --objects /path/to/quarantine-objects \
  --database sqlite:/path/to/quarantine.db
```

The command:

- imports pending and postponed encrypted items;
- decrypts locally, verifies the old envelope, and re-encrypts canonical content;
- preserves the original quarantine ID and postpone count;
- skips items already present, so rerunning is safe;
- reports finalized records and records without encrypted payloads separately;
- leaves the source JSONL and encrypted files untouched as a backup.

Finalized legacy records remain available in the source JSONL audit archive; they are not recreated as active SQL items. Verify the printed summary and SQL statistics before removing or archiving the legacy directory.

## Manual review

1. List pending items using the admin token.
2. Fetch an encrypted item response.
3. Decrypt locally:

```bash
npm run build
private-key-command | node dist/src/cli/decryptQuarantine.js encrypted-response.json
```

4. Choose one action:

- `approve`: send the complete decrypted object unchanged. The router canonicalizes it and compares its SHA-256 with the original stored digest before acting.
- `reject`: delete an unapproved retain/request item, or invalidate a rejected recalled memory in Hindsight.
- `postpone`: leave it reviewable and increment its postpone count.

Approval is exact-object only. Any change to content, context, tags, metadata, document identifiers, source, writer, reason, or timestamp produces `quarantine_hash_mismatch`. To alter a memory, reject the quarantined item and submit a new retain request.

For an approved retain request, the target bank comes from the current writer registry. The router writes the exact original body to Hindsight, removes the quarantine row, and keeps the approval event. For an approved recalled memory, the router removes ciphertext and records the SHA-256 of the safety-evaluated text as reviewed and allowed. Metadata-only changes do not force another review; changed text does.

Approval writes and recalled-memory invalidations hold the database review lock until the Hindsight action and local state transition complete. This prevents concurrent admin requests or multiple PostgreSQL-backed router instances from issuing the same action twice. Hindsight and the quarantine database are still separate systems, so a process crash or ambiguous network failure after Hindsight applies an action but before the database commit cannot be rolled back atomically. In that rare case, inspect Hindsight's audit/state before retrying; do not blindly repeat the admin action.

## Cleanup

Preview cleanup first:

```json
{
  "scope": "pending",
  "reasons": ["unknown_writer"],
  "older_than": "2026-07-01T00:00:00Z",
  "dry_run": true
}
```

Execute only with the returned count:

```json
{
  "scope": "pending",
  "reasons": ["unknown_writer"],
  "older_than": "2026-07-01T00:00:00Z",
  "dry_run": false,
  "expected_count": 42
}
```

If the selection changes between preview and execution, cleanup returns `409` rather than deleting a different set.

## Checks

```bash
npm run format:check
npm run lint
npm test
npm run test:coverage
npm run typecheck
npm run security:audit
npm run aislop:ci
```

CI also runs CodeQL, Gitleaks, Semgrep, Hadolint, Docker build, and fake/real Compose smoke tests. The fake stack exercises SQLite; the real Hindsight stack exercises PostgreSQL quarantine storage in a database separate from Hindsight's application database.

## License

MIT
