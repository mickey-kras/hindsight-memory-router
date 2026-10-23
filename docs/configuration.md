# Configuration

[Documentation](README.md) | [Repository](../README.md)

Environment variables override built-in defaults. The default wrap provider, `rsa-oaep`, must have `QUARANTINE_PUBLIC_KEY`. The `https-sidecar` provider must have its own [provider settings](security/quarantine.md#pluggable-dek-wrap-providers).

Use [`.env.example`](../.env.example) as an override template. Docker Compose reads your values from `.env`.

## Listener

The router binds `127.0.0.1:8890` by default. Set `MEMORY_ROUTER_HOST` and `MEMORY_ROUTER_PORT` to change the bind address and port.
The supplied Compose file permits access to the container listener but publishes the port only on host loopback.
Add a TLS terminator before you expose the API beyond the host. See [Docker deployment](deployment/docker.md).

## Credentials

Credentials have no defaults. Router and admin endpoints fail closed until you set the necessary tokens.

`MEMORY_ROUTER_ALLOW_ANONYMOUS=true` is a development-only override. Startup rejects it when `MEMORY_ROUTER_HOST` is not a loopback address. Explicit boolean values must be `true` or `false`.

## Registry

Without `MEMORY_ROUTER_REGISTRY`, the built-in `main` writer reads and writes only the `main` bank with `source: application`.

`writer_registry.example.json` keeps the earlier multi-writer example for deployments that use:

```text
MEMORY_ROUTER_REGISTRY=/app/writer_registry.example.json
```

Leave `MEMORY_ROUTER_REGISTRY` unset for the minimal default. Copy the example if you must have a custom policy for writers and banks.

Every writer's `write_bank` must also appear in its `read_banks`.
Invalid registries fail startup.

The router records the `source` of a writer in the retain and recall provenance and in the quarantine audit metadata. When you upgrade, do not change `source: "openclaw"` in OpenClaw writer entries. This keeps the existing audit filters.

Writer IDs use `[A-Za-z0-9._:-]{1,128}`.
The router rejects `.` and `..`.

## Storage

The default is `sqlite:./data/quarantine.db`. Set `QUARANTINE_DATABASE_URL` to an explicit SQLite URL or a PostgreSQL URL when necessary.

Cluster mode must have PostgreSQL and an external, shared admin rate limiter. See [clustered deployment](deployment/clustered.md).

## Tuning

Request bounds, timeouts, rate limits, quarantine capacities, sweep intervals, retention, and other settings have built-in defaults.
Startup validation rejects explicit invalid values. It does not use defaults for these values.

See [environment variables](reference/environment-variables.md) for the complete list.

