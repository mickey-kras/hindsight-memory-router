# Deployment modes

Set `MEMORY_ROUTER_DEPLOYMENT_MODE` explicitly in deployed environments.

## Single mode

```text
MEMORY_ROUTER_DEPLOYMENT_MODE=single
MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=false
```

Single mode permits SQLite or PostgreSQL quarantine storage. Quarantine and admin limits may be process-local when SQLite is used. Run one router process unless an upstream component already provides the required shared controls.

## Cluster mode

```text
MEMORY_ROUTER_DEPLOYMENT_MODE=cluster
MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true
QUARANTINE_DATABASE_URL=postgresql://...
```

Cluster mode fails startup unless:

- quarantine storage is PostgreSQL, which provides shared capacity, identity locking, and quarantine request limits across replicas;
- `MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true` declares that a reverse proxy, gateway, or distributed limiter enforces shared admin limits before requests reach any router replica.

The external limiter must distinguish authenticated admin reads from mutations and enforce limits equivalent to or stricter than:

```text
MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX=120
MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX=30
MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS=60000
```

`MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true` is an operator assertion. It does not install or configure a proxy. Setting it without an actual shared limiter removes the startup guard while leaving each router replica with its own built-in quota.

## Migration

To move from one process to multiple replicas:

1. Move quarantine storage to PostgreSQL and verify migration and readiness.
2. Configure and test the shared edge admin limiter.
3. Set cluster mode and the external-limiter assertion.
4. Restart one replica and verify `/ready`, router traffic, admin reads, and admin mutations.
5. Scale out only after the first replica passes verification.

To return to a single process, set `MEMORY_ROUTER_DEPLOYMENT_MODE=single`; do not silently keep cluster mode while removing PostgreSQL or the external limiter.
