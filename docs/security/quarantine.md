# Quarantine security

Unknown writers, suspicious requests, suspicious recalled memories, denied endpoints, and selected security events can be routed to encrypted quarantine.

Encryption boundary:

```text
payload -> canonical SHA-256 -> AES-256-GCM -> RSA-wrapped data key -> SQLite/PostgreSQL
```

The running router receives only the RSA public key. Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY` causes configured router startup to fail.

Generate the quarantine RSA keypair on a trusted admin machine. Keep the private key in a password manager, secret manager, or encrypted offline storage and provide only the public key to the router deployment. The default Docker Compose deployment never creates, mounts, or stores private review material.

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

Sidecar behavior is fail closed: one attempt per wrap (no retries, so a wrap can never be applied twice ambiguously), bounded by `QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS` (max 60000), responses streamed with a hard abort at 64 KiB and strictly validated, wrapped keys larger than `QUARANTINE_WRAP_SIDECAR_WRAPPED_KEY_BYTES` are rejected (size charging never undercounts), and transport/HTTP/validation failures surface as `502`/`504` without logging DEKs, payloads, tokens, or response bodies. The sidecar URL must use `https` (`http` is accepted only for loopback); the authentication boundary is an optional bearer token via `QUARANTINE_WRAP_SIDECAR_TOKEN`. Sidecar settings are rejected at startup unless `QUARANTINE_WRAP_PROVIDER=https-sidecar`.

Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY`, and any `QUARANTINE*` variable containing `UNWRAP`, causes router startup to fail: unwrap endpoints and private-key material must never reach the router process.

## Stored state and audit history

`quarantine_items` stores current encrypted state. `quarantine_events` stores audit history. Existing databases are migrated in place. Legacy rows keep `NULL` dedupe and expiry values, so they are neither merged nor expired automatically.

There is no Hindsight quarantine bank.

## Deduplication

Identical retain and recall quarantine requests reuse one pending item. The dedupe key covers request kind, writer, policy target, and canonical JSON payload. Object key order and JSON formatting do not matter; string content remains exact.

A repeated request refreshes the item, increments `requarantine_count`, and records `requarantined`. Repeats are rejected with `409` while the matching item is under review. Security-event identities are normalized by method and path, scoped by writer, and capped across the process.

## Capacity and retention

Quarantine item size, pending-item count, per-writer capacity, encrypted-byte capacity, request-family admission, requarantine operations, rate limits, item TTL, sweep cadence, and event retention all have safe built-in defaults and can be overridden explicitly.

Pending and postponed items expire after `QUARANTINE_ITEM_TTL_DAYS`; `0` disables expiry. The sweeper runs every `QUARANTINE_SWEEP_INTERVAL_SECONDS`; `0` disables it. Expired items stop counting toward capacity immediately and are later removed with a `cleanup` event.

Events older than `QUARANTINE_EVENT_RETENTION_DAYS` are pruned in batches of 1000; `0` keeps forever. Pruning is destructive and independent of item expiry. Set `QUARANTINE_EVENT_EXPORT_PATH` to append each pruned batch to a JSONL export file before deletion when long-term audit history is required.

Limit failures remain fail-closed:

- `413`: encrypted item too large;
- `429`: quarantine rate limit exceeded;
- `507`: quarantine capacity exhausted.

PostgreSQL quarantine rate limits are shared across router replicas and use PostgreSQL time. SQLite and in-memory limits are process-local.

See [quarantine review](../operations/quarantine-review.md) for offline decryption and review.
