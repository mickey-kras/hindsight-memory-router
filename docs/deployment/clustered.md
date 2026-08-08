# Clustered deployment

Single-node mode is the default. Enable clustered mode explicitly:

```text
MEMORY_ROUTER_DEPLOYMENT_MODE=cluster
```

Cluster mode fails startup unless both conditions are met:

- `QUARANTINE_DATABASE_URL` uses PostgreSQL;
- `MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true` confirms an equivalent or stricter shared admin limiter exists in front of the replicas.

PostgreSQL supplies shared quarantine and normal Hindsight quota state across replicas. Built-in admin throttling is process-local, which is why a shared external admin limiter is mandatory in cluster mode.

Do not use SQLite for multi-replica deployment.
