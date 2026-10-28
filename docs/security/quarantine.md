# Quarantine security

[Documentation](../README.md) | [Repository](../../README.md)

The router can send unknown writers, suspicious requests, suspicious recalled memories, denied endpoints, and selected security events to encrypted quarantine.

The default encryption boundary with RSA:

```text
payload -> canonical SHA-256 -> AES-256-GCM -> RSA-wrapped data key -> SQLite/PostgreSQL
```

With the default `rsa-oaep` provider, the running router gets only the RSA public key. Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY` causes configured router startup to fail.

For the default `rsa-oaep` provider, generate the quarantine RSA keypair on a trusted admin machine.
Keep the private key in a password manager, secret manager, or encrypted offline storage.
Give only the public key to the router deployment.
The default deployment with Docker Compose never creates, mounts, or stores private review material.

Example key generation on the trusted admin machine:

```bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out quarantine-private.pem
openssl pkey -in quarantine-private.pem -pubout -out quarantine-public.pem
```

There is no shared or default private key. Initial setup does not weaken quarantine encryption.

## Pluggable DEK wrap providers

The data-encryption key (DEK) wrap is pluggable behind one provider interface with two transports:

- `rsa-oaep` (default): the current in-process RSA-OAEP-SHA256 wrap. Envelopes do not change, and existing review tools can always decrypt them (`version: 1`, no `provider` block).
- `https-sidecar`: the router POSTs the freshly generated DEK to a configured wrap sidecar. It uses `POST {url}/wrap` with request `{"dek_b64": ...}` and response `{"wrapped_key_b64": ...}`. The router stores the returned wrapped key.

Provider envelopes keep `version: 1` and add an `encryption.provider` block (`{name, version}`).
AES-GCM AAD binds that block together with `key_wrap`. The offline review tool selects its unwrap method from that block.
The router never unwraps keys.
The PEM decryption routine for legacy envelopes rejects provider metadata without RSA fallback.
The separate authenticated [review agent](../operations/quarantine-review.md#provider-wrapped-and-hardware-key-review) selects a provider by exact `key_wrap` and `encryption.provider` identity.
It verifies the complete envelope before it returns the decrypted object to the console.
The envelope parser rejects malformed provider blocks and names that cannot pass the provider's own validation after serialization.

Sidecar behavior fails closed. The router calls the sidecar one time for each wrap, with no retry. This prevents ambiguous duplicate wraps.
`QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS` sets the time limit of each call (maximum 60000). The router stops the response stream at 64 KiB. The router strictly validates responses.

The router rejects wrapped keys larger than `QUARANTINE_WRAP_SIDECAR_WRAPPED_KEY_BYTES`. The size count is never too low.
Transport, HTTP, and validation failures return `502`/`504`. Logs exclude DEKs, payloads, tokens, and response bodies.
The sidecar URL must use `https`. The router accepts `http` only for loopback.

`QUARANTINE_WRAP_SIDECAR_TOKEN` supplies an optional bearer token for authentication.
Startup rejects sidecar settings unless `QUARANTINE_WRAP_PROVIDER=https-sidecar`.
Wrap requests send `Accept-Encoding: identity`. Responses must omit `Content-Encoding` or use `identity`.
The router rejects other encodings before body decoding.

Each quarantine store permits up to five active asynchronous wrap attempts. Attempts consume quota before they wait for a wrap slot.
The wrap step holds no database identity transaction or limiter connection. After the wrap, the router examines the review state, deduplication, and capacity again. It uses a short identity lock and an atomic storage transaction.
Failed or canceled admissions keep their quota charge.

Cancellation releases the local wrap slot. RSA work that runs in another thread can continue to completion. Remote sidecar work can also continue to completion.
For this reason, the slot limit is not a hard limit on that work.

Before wrapping, admission reads the row by its actual deduplication identity. It captures a fingerprint of the complete stored row.
The fingerprint includes the encrypted envelope, counters, review state, and metadata.
Existing identities use their stored quarantine ID during encryption and in the returned result. This includes legacy IDs.

After wrapping, the storage transaction locks the current row and compares it with the snapshot.
If an existing row changed, conflicting evidence returns `409 quarantine_write_stale`. The failure changes neither the item nor its events.
The same evidence with the same routing and security metadata can still refresh the item and increase `requarantine_count`.
This applies even when concurrent attempts have different server admission timestamps.

Under the row lock, this exception compares the incoming plaintext with one substitution. The incoming plaintext cannot change.
It replaces only incoming `created_at` with the current encrypted envelope’s valid `created_at`.
Every other plaintext field must match the stored SHA-256.
The transaction then stores and returns the incoming envelope and its actual SHA-256 normally.
A deduplication key alone never proves that two items of evidence are the same.

To retry after a conflict, start a new, complete admission. Include a new read and wrap.
Sequential changes succeed when the snapshot does not change. This applies even with equal timestamps or a replica clock that is behind.
Timestamps do not set the write order. Review-state conflicts have priority.

Rejected attempts keep their quota charge.

If cleanup or expiry removed the row, admission can insert it again if the row is not there at storage time.
The snapshot check protects changed existing evidence. It does not give a deletion tombstone.
The router suppresses recalled evidence that loses an admission race. It preserves unrelated safe recalled results.
Query and placeholder audit conflicts follow the existing degradation behavior.

Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY` causes router startup to fail.
Any `QUARANTINE*` variable containing `UNWRAP` also causes startup to fail.
Unwrap endpoints and private-key material must never reach the router process.

## Stored state and audit history

`quarantine_items` stores current encrypted state. `quarantine_events` stores audit history. The router migrates existing databases in place. Legacy rows keep `NULL` dedupe and expiry values. Thus, the router does not merge them or let them expire automatically.

Admin review mutations (approve, reject, postpone, reconcile, cleanup) record the authenticated actor in event details.
The actor is the matched admin token scope (`read`, `review`, `cleanup`, or `legacy`). Event details never contain the token.
Each mutation also emits an `admin_action` log event. This event contains the same actor identity, the action, and the quarantine id.
Log throttling never suppresses this audit event.

There is no Hindsight quarantine bank.

## Deduplication

If two retain or recall quarantine requests are the same, they share one pending item. The dedupe key covers request kind, writer, policy target, and canonical JSON payload. Object key order and JSON formatting do not matter. String content must be exact.

A repeated request refreshes the item, increases `requarantine_count`, and records `requarantined`.
Repeats return `409` while the matching item is under review.
Security-event identities preserve exact producer keys. Their scope includes the writer or principal, the bank, the source, and the reason.
The database can store at most 64 distinct security-event items, including reviewed and expired items.

New identities return `507 quarantine_security_event_capacity_exceeded` until cleanup removes an item.
Repeats can refresh an existing identity. SQLite transactions and the capacity lock of PostgreSQL enforce this admission bound across restarts and replicas.
Existing rows count toward the limit. Pre-upgrade security-event keys do not change and do not combine with new scoped identities.
Cleanup can be necessary before admission of new identities.

## Capacity and retention

Quarantine limits have safe built-in defaults.
These include item size, pending-item count, per-writer capacity, encrypted-byte capacity, request-family admission, requarantine operations, and rate limits.
Item TTL, sweep intervals, and event retention also have defaults.
You can override each value explicitly.

Attributed security events use the same pending capacities of the writer or principal and of the bank as other quarantine items.
Denied endpoints charge a principal bank only when the principal has a grant for that exact bank.
Requested paths without grants stay encrypted evidence but do not charge that bank.
Legacy denied endpoints resolve registered writer names to their configured write bank.
Only anonymous `auth_failed` events without a writer or bank are exempt from scoped capacities.
They still consume global item, byte, and security-event identity capacity.

The router writes a log entry when it cannot save an audit record. Authentication failures and unsafe-content blocks stay fail-closed.

Pending and postponed items expire after `QUARANTINE_ITEM_TTL_DAYS`. `0` disables expiry. The sweeper runs every `QUARANTINE_SWEEP_INTERVAL_SECONDS`. `0` disables the sweeper. Expired items immediately stop their count toward capacity. Later, the sweeper removes them with a `cleanup` event.

The router prunes events older than `QUARANTINE_EVENT_RETENTION_DAYS` in batches of 1000. A value of `0` keeps events forever.
Pruning is destructive and independent of item expiry.
For long-term audit history, set `QUARANTINE_EVENT_EXPORT_PATH` to a JSONL export file.
The router appends each pruned batch to that file before deletion.
Export runs in a worker thread and completes before deletion.

Cancellation waits for the worker to finish before the batch rolls back.
The export includes completed records at least once. Retry consumers must deduplicate by `event_id`.
Write failures can leave a partial final record. See [cleanup](../operations/cleanup.md) for retry and durability limits.

Limit failures stay fail-closed:

- `413`: The encrypted item is too large.
- `429`: Too many quarantine writes in the configured time window.
- `507`: The quarantine has no capacity.

All router replicas share the quarantine rate limits in PostgreSQL. These limits use the PostgreSQL clock. SQLite and in-memory limits are process-local.

See [quarantine review](../operations/quarantine-review.md) for offline decryption and review.


