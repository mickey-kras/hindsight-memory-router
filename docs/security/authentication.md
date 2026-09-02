# Authentication

Memory Router separates router access from quarantine administration.

## Principal mode (per-agent)

Set `MEMORY_ROUTER_PRINCIPALS` to a principal registry JSON file (see
`principal_registry.example.json`) to give every agent its own credential and
per-bank grants. Principal mode replaces the shared router token:
`MEMORY_ROUTER_TOKEN` and `MEMORY_ROUTER_ALLOW_ANONYMOUS=true` are rejected at
startup when a registry is configured.

Tokens have the format `mr_<key-id>_<256-bit-secret-hex>`. The registry stores
SHA-256 digests of the secret only; verification hashes the presented secret
and compares digests in constant time with an O(1) key-id lookup. A principal
can hold several keys at once so rotation overlaps: add the new key, restart,
move clients, remove the old key, restart.

Grants pair a bank with scopes from a fixed vocabulary: `banks:list`,
`banks:read`, `banks:manage`, `memories:retain`, `memories:recall`,
`memories:read`, `memories:write`, `reflect:run`, `operations:manage`.
Evaluation is default deny; `GET /v1/default/banks` returns only banks where
the principal holds `banks:list`. The optional `x-memory-router-agent` header
must name the authenticated principal when present; a mismatch is rejected.

Denials and failures are audited with principal and key-id fields. Raw tokens,
digests, and authorization headers are never logged.

## Legacy shared token

Router retain/recall access uses `MEMORY_ROUTER_TOKEN`. If no router token is configured, those endpoints fail closed unless the development-only `MEMORY_ROUTER_ALLOW_ANONYMOUS=true` override is enabled. `/version` is unauthenticated for Hindsight compatibility.

Admin capabilities use separate scoped tokens:

- `MEMORY_ROUTER_ADMIN_READ_TOKEN`: queue/statistics/encrypted-item reads;
- `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`: read plus approve/reject/postpone;
- `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`: cleanup only.

`MEMORY_ROUTER_ADMIN_TOKEN` remains a legacy migration superuser for every admin route and should be unset after clients move to scoped tokens.

Token comparison is constant-time. Token values are never logged or stored. Failed authentication is logged and passes through a process-local failure gate. Admitted invalid-token attempts create one deduplicated `auth_failed` item per route group; gate-rejected and valid-but-mis-scoped attempts are not persisted. Mis-scoped attempts consume the failure budget. Admin reads and writes have separate process-local limits.

## Scope boundaries

A leaked read token cannot mutate quarantine state. A leaked cleanup token cannot inspect encrypted envelopes or make review decisions. A leaked review token can read encrypted envelopes and run review actions, but cannot execute bulk cleanup. No admin token can decrypt envelopes or approve modified content.

## Migration from the legacy admin token

1. Generate independent read, review, and cleanup tokens.
2. Configure the scoped tokens while temporarily retaining `MEMORY_ROUTER_ADMIN_TOKEN`, then restart the router.
3. Update each admin client to use only the token matching its responsibilities.
4. Verify every scoped client works and confirm the startup warning still reports the legacy migration superuser as active.
5. Unset `MEMORY_ROUTER_ADMIN_TOKEN` and restart the router again.
6. Rotate any individual scoped token without changing the others.
7. Review quarantine events if compromise is suspected.

Keep tokens out of prompts, logs, shell history, and committed configuration.
