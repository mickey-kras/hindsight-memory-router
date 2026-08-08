# Authentication

Memory Router separates router access from quarantine administration.

Router retain/recall/version access uses `MEMORY_ROUTER_TOKEN`. If no router token is configured, those endpoints fail closed unless the development-only `MEMORY_ROUTER_ALLOW_ANONYMOUS=true` override is explicitly enabled.

Admin capabilities use separate scoped tokens:

- `MEMORY_ROUTER_ADMIN_READ_TOKEN`: queue/statistics/encrypted-item reads;
- `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`: read plus approve/reject/postpone;
- `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`: cleanup only.

`MEMORY_ROUTER_ADMIN_TOKEN` remains a legacy migration superuser and should normally be unset.

Token comparison is constant-time. Token values are not stored in quarantine. Failed authentication is audited as a deduplicated security event and does not consume normal admin quota.

Generate independent secrets, keep them out of source control/logs/prompts, and rotate scopes independently.
