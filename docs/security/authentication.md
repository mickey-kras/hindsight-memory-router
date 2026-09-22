# Authentication

Router and quarantine credentials are separate.

Set legacy router and admin tokens to at least 32 characters. Shorter tokens block startup.

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
- `quarantine.review`: read-only principal access to `GET /admin/quarantine/queue` and `GET /admin/quarantine/stats` metadata for granted banks; ciphertext fetch and review actions still require admin tokens
- `quarantine.decide`: reserved; no endpoints

Authorization is default-deny per principal, bank, and scope. `GET /v1/default/banks` keeps the upstream response shape and removes ungranted banks.

Facade reads of memory graphs, audit-log entries, LLM request traces, and operation payloads require `memory.recall`. Operation status without payloads and aggregate audit/LLM statistics keep `bank.config.read`. For operation detail, any true `include_payload` value requires `memory.recall`, including repeated query parameters; invalid boolean values return `400` in principal mode.

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

Cluster mode stores principal rate counters and concurrency leases in PostgreSQL. PostgreSQL
availability is required for authenticated principal requests.

### Audit

`authorization_decision`: request ID, principal, key ID, bank, scope, decision, status, latency, source. No token, digest, or Authorization header. Successful authentications are not logged; failed attempts emit `authentication_failed`.

### Rotation

1. Add new key digest.
2. Restart router.
3. Update client token.
4. Set old `revoked_at`; restart.

## Legacy router token (deprecated)

`MEMORY_ROUTER_TOKEN` protects router endpoints when principal mode is off. Missing token fails closed unless `MEMORY_ROUTER_ALLOW_ANONYMOUS=true`. Anonymous mode is development-only: startup rejects it unless `MEMORY_ROUTER_HOST` is a loopback address.

Legacy token mode is deprecated and is removed at the next major release: startup logs a `legacy-router-token` configuration warning and authenticated responses carry a `Deprecation` header. Migrate to principal mode: create a principal registry (see `principal_registry.example.json`) with one principal per writer (unique key ID, SHA-256 secret digest, bank and scope grants), set `MEMORY_ROUTER_PRINCIPALS` to its path, unset `MEMORY_ROUTER_TOKEN`, and issue each caller a `mr_<key-id>_<secret>` token.

`/health/live` is anonymous and static. `/health/ready`, `/health`, and `/ready` answer anonymous callers with only `{"status": ...}`; the full upstream readiness payload requires router authentication. `/version` requires router authentication.

Legacy-mode memory operations are not logged on success; blocked or suspicious operations land in the quarantine review queue.

## Quarantine admin

- `MEMORY_ROUTER_ADMIN_READ_TOKEN`: read
- `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`: read and decide
- `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`: cleanup
- `MEMORY_ROUTER_ADMIN_TOKEN`: legacy all-scope superuser; deprecated and removed at the next major release (authenticated responses carry a `Deprecation` header)

Keep tokens out of Git, files, logs, prompts, and shell history.
