# Quarantine security

[Documentation](../README.md) | [Repository](../../README.md)

Unknown writers, suspicious requests, suspicious recalled memories, denied endpoints, and selected security events can be routed to encrypted quarantine.

Default RSA encryption boundary:

```text
payload -> canonical SHA-256 -> AES-256-GCM -> RSA-wrapped data key -> SQLite/PostgreSQL
```

With the default `rsa-oaep` provider, the running router receives only the RSA public key. Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY` causes configured router startup to fail.

For the default `rsa-oaep` provider, generate the quarantine RSA keypair on a trusted admin machine. Keep the private key in a password manager, secret manager, or encrypted offline storage and provide only the public key to the router deployment. The default Docker Compose deployment never creates, mounts, or stores private review material.

Example key generation on the trusted admin machine:

```bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out quarantine-private.pem
openssl pkey -in quarantine-private.pem -pubout -out quarantine-public.pem
```

There is no shared/default private key and quarantine encryption is not weakened for onboarding.

## Pluggable DEK wrap providers

The data-encryption key (DEK) wrap is pluggable behind one provider interface with two transports:

- `rsa-oaep` (default): the current in-process RSA-OAEP-SHA256 wrap. Envelopes are unchanged and stay decryptable by existing review tooling forever (`version: 1`, no `provider` block).
- `https-sidecar`: the router POSTs the freshly generated DEK to a configured wrap sidecar (`POST {url}/wrap`, request `{"dek_b64": ...}`, response `{"wrapped_key_b64": ...}`) and stores the returned wrapped key.

Provider envelopes keep `version: 1` and add an `encryption.provider` block (`{name, version}`) that is bound into the AES-GCM AAD together with `key_wrap`. The offline review tool selects its unwrap path from that block. The router never unwraps: local decryption fails closed on every provider envelope (never an RSA fallback), and envelope parsing strict-rejects malformed provider blocks and provider names that cannot round-trip through its own validation.

Sidecar behavior is fail closed: one attempt per wrap (no retries, so a wrap can never be applied twice ambiguously), bounded by `QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS` (max 60000), responses streamed with a hard abort at 64 KiB and strictly validated, wrapped keys larger than `QUARANTINE_WRAP_SIDECAR_WRAPPED_KEY_BYTES` are rejected (size charging never undercounts), and transport/HTTP/validation failures surface as `502`/`504` without logging DEKs, payloads, tokens, or response bodies. The sidecar URL must use `https` (`http` is accepted only for loopback); the authentication boundary is an optional bearer token via `QUARANTINE_WRAP_SIDECAR_TOKEN`. Sidecar settings are rejected at startup unless `QUARANTINE_WRAP_PROVIDER=https-sidecar`. Wrap requests send `Accept-Encoding: identity`; responses must omit `Content-Encoding` or use `identity`, and other encodings are rejected before body decoding.

Each quarantine store permits up to five active asynchronous wrap attempts. Attempt quotas are charged before waiting for a wrap slot, and wrapping holds no database identity transaction or limiter connection. After wrapping, a short identity lock and the repository's atomic storage transaction recheck review state, dedupe, and capacity. Failed or cancelled attempts keep their quota charge. Cancellation releases the local wrap slot; already-running RSA work in an offloaded thread or work at the remote sidecar may finish afterward, so this limit does not impose a hard cap on that underlying work.

Before wrapping, admission reads the row by its actual dedupe identity and captures a fingerprint of the entire stored row, including its encrypted envelope, counters, review state, and metadata. Existing identities use their persisted quarantine ID when encrypting and returning the result, including legacy IDs. After wrapping, the storage transaction compares that snapshot with the current row under its lock. If an extant row changed, conflicting evidence fails with `409 quarantine_write_stale` without changing the item or its events. Identical evidence with matching routing/security metadata may still refresh and increment `requarantine_count`, even when concurrent attempts have different server admission timestamps. Under the row lock, this exception compares the immutable incoming plaintext with only its `created_at` replaced by the current encrypted envelope’s valid `created_at`; every other plaintext field must match the stored SHA-256. The incoming envelope and its actual SHA-256 are then persisted and returned normally. A dedupe key alone never proves evidence is identical. Retry a conflict through a fresh full admission attempt, including a new read and wrap. Sequential changes succeed when the snapshot remains unchanged, even with equal timestamps or a lagging replica clock; timestamps do not determine write order. Review-state conflicts take precedence, and rejected attempts keep their quota charge.

If cleanup or expiry removed the row and it remains absent at storage time, admission may insert it again. This snapshot check protects changed extant evidence and does not provide a deletion tombstone. Recalled evidence that loses an admission race is suppressed while unrelated safe recalled results are preserved; query and placeholder audit conflicts follow the existing degradation behavior.

Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY`, and any `QUARANTINE*` variable containing `UNWRAP`, causes router startup to fail: unwrap endpoints and private-key material must never reach the router process.

## Stored state and audit history

`quarantine_items` stores current encrypted state. `quarantine_events` stores audit history. Existing databases are migrated in place. Legacy rows keep `NULL` dedupe and expiry values, so they are neither merged nor expired automatically.

Admin review mutations (approve, reject, postpone, reconcile, cleanup) record the authenticated actor in the event details: the matched admin token scope (`read`, `review`, `cleanup`, or `legacy`), never the token itself. Each mutation also emits an `admin_action` log event with the same actor identity, the action, and the quarantine id; this audit event is never log-throttled.

There is no Hindsight quarantine bank.

## Deduplication

Identical retain and recall quarantine requests reuse one pending item. The dedupe key covers request kind, writer, policy target, and canonical JSON payload. Object key order and JSON formatting do not matter; string content remains exact.

A repeated request refreshes the item, increments `requarantine_count`, and records `requarantined`. Repeats are rejected with `409` while the matching item is under review. Security-event identities preserve exact producer keys and are scoped by writer/principal, bank, source, and reason. At most 64 distinct security-event items may be stored across the database, including reviewed and expired items. New identities fail with `507 quarantine_security_event_capacity_exceeded` until cleanup removes an item; repeats can refresh an existing identity. SQLite transactions and the PostgreSQL capacity lock enforce this admission bound across restarts and replicas. Existing rows count toward the limit. Pre-upgrade security-event keys remain unchanged and do not coalesce with new scoped identities; cleanup may be required before new identities can be admitted.

## Capacity and retention

Quarantine item size, pending-item count, per-writer capacity, encrypted-byte capacity, request-family admission, requarantine operations, rate limits, item TTL, sweep cadence, and event retention all have safe built-in defaults and can be overridden explicitly.

Attributed security events consume the same writer/principal and bank pending capacities as other quarantine items. Denied endpoints charge a principal bank only when the principal has a grant for that exact bank; ungranted requested paths remain encrypted evidence without charging that bank. Legacy denied endpoints resolve registered writer names to their configured write bank. Only anonymous `auth_failed` events with no writer or bank are exempt from scoped capacities; they still consume global item, byte, and security-event identity capacity. Audit persistence failures are logged; authentication failures and unsafe-content blocking remain fail-closed.

Pending and postponed items expire after `QUARANTINE_ITEM_TTL_DAYS`; `0` disables expiry. The sweeper runs every `QUARANTINE_SWEEP_INTERVAL_SECONDS`; `0` disables it. Expired items stop counting toward capacity immediately and are later removed with a `cleanup` event.

Events older than `QUARANTINE_EVENT_RETENTION_DAYS` are pruned in batches of 1000; `0` keeps forever. Pruning is destructive and independent of item expiry. Set `QUARANTINE_EVENT_EXPORT_PATH` to append each pruned batch to a JSONL export file before deletion when long-term audit history is required. Export runs in a worker thread and completes before deletion; cancellation drains the worker before rolling back the batch. Completed records are exported at least once, so retry consumers must deduplicate by `event_id`. Write failures can leave a partial final record; see [cleanup](../operations/cleanup.md) for retry and durability limits.

Limit failures remain fail-closed:

- `413`: encrypted item too large;
- `429`: quarantine rate limit exceeded;
- `507`: quarantine capacity exhausted.

PostgreSQL quarantine rate limits are shared across router replicas and use PostgreSQL time. SQLite and in-memory limits are process-local.

See [quarantine review](../operations/quarantine-review.md) for offline decryption and review.
