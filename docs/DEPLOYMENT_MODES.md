# Deployment modes

[Documentation](README.md) | [Repository](../README.md)

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

Necessary:

- PostgreSQL. All replicas share the Hindsight, quarantine, principal, admin, and auth-failure limits.
- External admin limiter before all replicas.

Authentication failures also pass through a local prefilter before PostgreSQL.

Minimum shared admin limits:

```text
reads:  120 / 60s
writes: 30 / 60s
```

The external-limiter flag only confirms the admin limiter exists.

## Scale out

1. Migrate quarantine to PostgreSQL.
2. Configure the shared admin limiter.
   Test the shared admin limiter.
3. Enable cluster mode.
4. Restart one replica.
   Examine that replica.
5. Add replicas.

To roll back, reduce the deployment to one replica.
Set the mode to `single`.

