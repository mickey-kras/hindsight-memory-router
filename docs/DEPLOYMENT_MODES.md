# Deployment modes

## Single

```text
MEMORY_ROUTER_DEPLOYMENT_MODE=single
MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=false
```

Use one router process. SQLite keeps limits local. PostgreSQL shares limits and must stay available.

## Cluster

```text
MEMORY_ROUTER_DEPLOYMENT_MODE=cluster
MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true
QUARANTINE_DATABASE_URL=postgresql://...
```

Required:

- PostgreSQL; Hindsight, quarantine, principal, admin, and auth-failure limits are shared across replicas.
- External admin limiter before all replicas.

Auth failures also hit a local prefilter before PostgreSQL.

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
