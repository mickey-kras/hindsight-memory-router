# Configuration

Memory Router ships with safe defaults. Environment variables override them. `QUARANTINE_PUBLIC_KEY` is required.

Use `.env.example` as the complete reference. Docker Compose reads your values from `.env`.

## Credentials

Credentials have no defaults. Router and admin endpoints fail closed until you set the required tokens.

`MEMORY_ROUTER_ALLOW_ANONYMOUS=true` is a development-only override. Explicit boolean values must be `true` or `false`.

## Registry

Without `MEMORY_ROUTER_REGISTRY`, the built-in `main` writer reads and writes only the `main` bank with `source: application`.

`writer_registry.example.json` keeps the earlier multi-writer example for deployments that use:

```text
MEMORY_ROUTER_REGISTRY=/app/writer_registry.example.json
```

Leave `MEMORY_ROUTER_REGISTRY` unset for the minimal default. Copy the example when you need custom writer/bank policy.

Every writer's `write_bank` must also appear in its `read_banks`; invalid registries fail startup.

Writer IDs use `[A-Za-z0-9._:-]{1,128}`; `.` and `..` are rejected.

## Storage

The default is `sqlite:./data/quarantine.db`. Set `QUARANTINE_DATABASE_URL` to an explicit SQLite URL or a PostgreSQL URL when needed.

Cluster mode requires PostgreSQL plus an external/shared admin rate limiter. See [clustered deployment](deployment/clustered.md).

## Tuning

Request bounds, timeouts, rate limits, quarantine capacities, sweep cadence, retention, and other tuning values all have built-in defaults. Explicit invalid values fail startup validation rather than silently falling back.

See [environment variables](reference/environment-variables.md) for the complete list.
