# Authentication

Memory Router separates router access from quarantine administration.

Router retain/recall/version access uses `MEMORY_ROUTER_TOKEN`. If no router token is configured, those endpoints fail closed unless the development-only `MEMORY_ROUTER_ALLOW_ANONYMOUS=true` override is explicitly enabled.

Admin capabilities use separate scoped tokens:

- `MEMORY_ROUTER_ADMIN_READ_TOKEN`: queue/statistics/encrypted-item reads;
- `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`: read plus approve/reject/postpone;
- `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`: cleanup only.

`MEMORY_ROUTER_ADMIN_TOKEN` remains a legacy migration superuser for every admin route and should be unset after clients move to scoped tokens.

Token comparison is constant-time. Token values are never logged or stored in quarantine. Failed authentication creates one deduplicated `auth_failed` item per route group and does not consume normal admin quota. Admin reads and writes have separate process-local sliding-window limits.

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
