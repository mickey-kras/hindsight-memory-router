# Clustered deployment

[Documentation](../README.md) | [Repository](../../README.md)

Single-node mode is the default. Enable clustered mode explicitly:

```text
MEMORY_ROUTER_DEPLOYMENT_MODE=cluster
```

Cluster mode stops at startup if one of these conditions is false:

- `QUARANTINE_DATABASE_URL` uses PostgreSQL.
- `MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true` confirms that a shared admin limiter is in front of the replicas. Its limits must be the same or stricter.

PostgreSQL supplies shared quarantine, Hindsight quota, and the rate and concurrency state of principals across replicas.
Principal traffic fails closed with `503` if shared limit storage is unavailable.
Built-in authentication-failure and admin throttling also use shared PostgreSQL state.
The authentication prefilter stays local to each process.
Cluster mode must have a shared external admin limiter.

Do not use SQLite for multi-replica deployment.

Optional human login uses PostgreSQL for one-use exchanges, session revocation, and shared rate and concurrency limits.
All replicas must use the same active human policy generation.
Run `memory-router-human-auth activate` when you change that configuration.
Activation immediately invalidates the sessions from before and causes stale replicas to fail closed.
Human traffic fails closed if the shared state is not available or does not match.

