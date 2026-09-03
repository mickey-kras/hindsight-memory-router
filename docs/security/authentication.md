# Authentication

Router and quarantine credentials are separate.

## Principal mode

Set `MEMORY_ROUTER_PRINCIPALS=/path/principals.json`. This disables the shared router token. Startup rejects:

- `MEMORY_ROUTER_TOKEN`
- `MEMORY_ROUTER_ALLOW_ANONYMOUS=true`

Token: `mr_<key-id>_<64-lowercase-hex-secret>`.

Registry: SHA-256 secret digest only. Keys support `created_at`, `expires_at`, `revoked_at`. Key IDs are globally unique.

Scopes:

- `bank.list`
- `memory.recall`
- `memory.retain`
- `memory.reflect`
- `bank.config.read`
- `bank.config.write`
- `bank.admin`
- `quarantine.review` and `quarantine.decide`: reserved; no endpoints

Authorization is default-deny per principal, bank, and scope. `GET /v1/default/banks` keeps the upstream response shape and removes ungranted banks.

Optional `x-memory-router-agent`: must equal the token principal.

### Limits

| Class | Requests/min | Concurrency | Body |
| --- | ---: | ---: | ---: |
| recall | 120 | 4 | 32 KiB |
| retain | 30 | 2 | 512 KiB |
| reflect | 30 | 2 | 32 KiB |
| config/list | 60 | 2 | 128 KiB |
| admin | 10 | 1 | 128 KiB |

Override under registry `defaults.limits.<class>` or `principals.<id>.limits.<class>`:

- `rate_limit_max`
- `rate_limit_window_ms`
- `concurrency_max`
- `max_body_bytes`

Principal body limits cannot exceed `MEMORY_ROUTER_MAX_BODY_BYTES`.

### Audit

`authorization_decision`: request ID, principal, key ID, bank, scope, decision, status, latency, source. No token, digest, or Authorization header.

### Rotation

1. Add new key digest.
2. Restart router.
3. Update client token.
4. Set old `revoked_at`; restart.

## Legacy router token

`MEMORY_ROUTER_TOKEN` protects router endpoints when principal mode is off. Missing token fails closed unless `MEMORY_ROUTER_ALLOW_ANONYMOUS=true`.

`/version` and health endpoints are unauthenticated.

## Quarantine admin

- `MEMORY_ROUTER_ADMIN_READ_TOKEN`: read
- `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`: read and decide
- `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`: cleanup
- `MEMORY_ROUTER_ADMIN_TOKEN`: legacy superuser; remove after migration

Keep tokens out of Git, files, logs, prompts, and shell history.
