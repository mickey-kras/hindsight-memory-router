# Deployment modes

## Single

```text
MEMORY_ROUTER_DEPLOYMENT_MODE=single
MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=false
```

Use one router process. SQLite or PostgreSQL is supported. SQLite keeps Hindsight and quarantine rate limits process-local.

## Cluster

```text
MEMORY_ROUTER_DEPLOYMENT_MODE=cluster
MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true
QUARANTINE_DATABASE_URL=postgresql://...
```

Required:

- PostgreSQL quarantine database; Hindsight, quarantine, and principal limits are shared across replicas.
- Shared admin limiter before all replicas.

Minimum shared admin limits:

```text
reads:  120 / 60s
writes: 30 / 60s
```

The external-limiter flag only confirms the admin limiter exists.

## Scale out

1. Migrate quarantine to PostgreSQL.
2. Configure and test the shared admin limiter.
3. Enable cluster mode.
4. Restart and verify one replica.
5. Add replicas.

Rollback: return to one replica and set mode to `single`.
