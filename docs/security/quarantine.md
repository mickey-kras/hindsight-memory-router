# Quarantine security

Unknown writers, suspicious requests, suspicious recalled memories, denied endpoints, and selected security events can be routed to encrypted quarantine.

Encryption boundary:

```text
payload -> canonical SHA-256 -> AES-256-GCM -> RSA-wrapped data key -> SQLite/PostgreSQL
```

The running router receives only the RSA public key. Any environment variable whose name begins with `QUARANTINE_PRIVATE_KEY` causes configured router startup to fail.

Docker Compose generates the keypair with a one-shot initializer. The public key is mounted read-only into the router. Private review material is stored separately in the project-scoped `memory-router-private-key` Compose volume and is never mounted into the router service. The initializer runs with networking disabled.

There is no shared/default private key and quarantine encryption is not weakened for onboarding.

## Capacity and retention

Quarantine item size, pending-item count, per-writer capacity, encrypted-byte capacity, request-family admission, requarantine operations, rate limits, item TTL, sweep cadence, and event retention all have safe built-in defaults and can be overridden explicitly.

Limit failures remain fail-closed:

- `413`: encrypted item too large;
- `429`: quarantine rate limit exceeded;
- `507`: quarantine capacity exhausted.

See [quarantine review](../operations/quarantine-review.md) for offline decryption and review.
