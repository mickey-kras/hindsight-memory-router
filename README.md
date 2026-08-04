# Hindsight Memory Router

Deterministic, fail-closed policy facade between OpenClaw (or any agent runtime) and a Hindsight-compatible memory service. The router enforces writer identity, per-writer bank ACLs, and deterministic safety filtering, and quarantines everything it cannot safely accept or return.

## Quickstart

Requires Node.js 22.5+ (`node:sqlite` for the default quarantine store).

```bash
npm ci
npm run dev
```

Configuration via environment:

```bash
MEMORY_ROUTER_PORT=8080
HINDSIGHT_BASE_URL=http://localhost:7070
HINDSIGHT_TOKEN=...
WRITER_REGISTRY_PATH=./writers.json
QUARANTINE_PUBLIC_KEY_PATH=./quarantine-public.pem
```

Example `writers.json`:

```json
{
  "writers": {
    "agent-ops": {
      "role": "ops",
      "source": "openclaw",
      "write_bank": "ops",
      "read_banks": ["ops", "core"]
    }
  }
}
```

## Images

GHCR is canonical; Docker Hub is a mirror.

```bash
docker pull ghcr.io/mickey-kras/hindsight-memory-router:latest
```

Pin deployments by digest:

```bash
docker pull ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest>
```

`latest` remains available for convenience but is mutable. The publish workflow records both registry digests in the job summary and an `image-digests-<commit>` artifact.

Images are signed with cosign keyless signing:

```bash
cosign verify ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/mickey-kras/hindsight-memory-router/.github/workflows/publish.yml.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## API

OpenClaw-compatible surface:

- `POST /v1/retain` — body `{items: [{content, metadata?}]}`
- `POST /v1/recall` — body `{query, limit?}`

Writer identity comes from the `x-memory-writer` header; unknown writers are quarantined, never silently mapped.

Admin review API (behind admin auth):

- `GET /admin/quarantine` — list reviewable items (pending/postponed)
- `GET /admin/quarantine/:id` — fetch one item (encrypted envelope)
- `POST /admin/quarantine/:id/postpone` — defer an item
- `POST /admin/quarantine/:id/approve` — approve per item kind (retain into Hindsight / allow recalled memory)
- `POST /admin/quarantine/:id/reject` — reject (recalled memories are invalidated upstream)

Responses for quarantined user content are encrypted envelopes; decryption stays local (`npm run quarantine:decrypt`).

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

Recall degrades gracefully instead of failing the whole request:

```text
one read bank errors -> that bank contributes zero results; healthy banks answer
all read banks error -> empty results (no 5xx)
queue full (507) or rate limited (429) at recall ->
    suspicious content is still suppressed, and unknown writers or suspicious
    queries still get empty results; the recall itself stays a 200
repeat of a suspicious request already under review (409) -> same degradation
```

Every degradation is logged as a structured `memory-router recall degraded: {...}` line on stderr so suppression without a quarantine record is observable. Other error types (programming or infrastructure failures) still propagate unchanged. Retain does not degrade: a retain that cannot quarantine suspicious content still fails closed with `507`.

There is no Hindsight quarantine bank.

## Quarantine

`quarantine_items` stores current encrypted state. `quarantine_events` stores audit history. Existing databases are migrated in place at startup; rows created before deduplication keep a `NULL` dedupe key and are never merged.

```text
payload -> canonical SHA-256 -> AES-256-GCM envelope -> SQLite/PostgreSQL
```

The router stores only the public key. Any `QUARANTINE_PRIVATE_KEY*` environment variable makes startup fail.

### Deduplication

Identical retain and recall quarantine requests reuse one pending item. The dedupe key covers request kind, writer, policy target, and canonical JSON payload. Object key order and JSON formatting do not matter; string content remains exact. A repeat refreshes the item, increments `requarantine_count`, and records `requarantined`. Repeats are rejected with `409` while the matching item is under review. Security-event identities are normalized by method and path, scoped by writer, and capped across the process.

Limits fail closed:

- `413`: item too large;
- `429`: rate limit exceeded;
- `507`: quarantine capacity exhausted.

PostgreSQL rate limits are shared across router replicas and use PostgreSQL time. SQLite and in-memory limits are process-local.

## Development

```bash
npm run check        # format, lint, openapi, tests+coverage, typecheck, audit, aislop
```

Coverage gates: 90% lines, 85% branches.
