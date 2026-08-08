# Quarantine security

Unknown writers, suspicious requests, suspicious recalled memories, denied endpoints, and selected security events can be routed to encrypted quarantine.

Before policy decisions, text passes through deterministic normalization/bounds and selected OWASP Agent Memory Guard detectors in-process. AMG is an additional detector layer; it does not own Memory Router storage, quarantine, or review state.

Encryption boundary:

```text
payload -> canonical SHA-256 -> AES-256-GCM -> RSA-wrapped data key -> SQLite/PostgreSQL
```

The running router receives only the RSA public key. Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY` causes configured router startup to fail.

Docker Compose generates the keypair with a one-shot initializer. The public key is mounted read-only into the router. Private review material is stored separately in the project-scoped `memory-router-private-key` Compose volume and is never mounted into the router service. The initializer runs with networking disabled.

There is no shared/default private key and quarantine encryption is not weakened for onboarding.

## Stored state and audit history

`quarantine_items` stores current encrypted state. `quarantine_events` stores audit history. Existing databases are migrated in place. Legacy rows keep `NULL` dedupe and expiry values, so they are neither merged nor expired automatically.

There is no Hindsight quarantine bank.

## Deduplication

Identical retain and recall quarantine requests reuse one pending item. The dedupe key covers request kind, writer, policy target, and canonical JSON payload. Object key order and JSON formatting do not matter; string content remains exact.

A repeated request refreshes the item, increments `requarantine_count`, and records `requarantined`. Repeats are rejected with `409` while the matching item is under review. Security-event identities are normalized by method and path, scoped by writer, and capped across the process.

## Capacity and retention

Quarantine item size, pending-item count, per-writer capacity, encrypted-byte capacity, request-family admission, requarantine operations, rate limits, item TTL, sweep cadence, and event retention all have safe built-in defaults and can be overridden explicitly.

Pending and postponed items expire after `QUARANTINE_ITEM_TTL_DAYS`; `0` disables expiry. The sweeper runs every `QUARANTINE_SWEEP_INTERVAL_SECONDS`; `0` disables it. Expired items stop counting toward capacity immediately and are later removed with a `cleanup` event.

Events older than `QUARANTINE_EVENT_RETENTION_DAYS` are pruned in batches of 1000; `0` keeps them forever. Pruning is destructive and independent of item expiry, so export events first when long-term audit history is required.

Limit failures remain fail-closed:

- `413`: encrypted item too large;
- `429`: quarantine rate limit exceeded;
- `507`: quarantine capacity exhausted.

PostgreSQL quarantine rate limits are shared across router replicas and use PostgreSQL time. SQLite and in-memory limits are process-local.

See [quarantine review](../operations/quarantine-review.md) for offline decryption and review.
