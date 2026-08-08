# Configuration

Memory Router is designed to start with safe built-in defaults. Environment variables are overrides, not required setup.

Use `.env.example` as the complete override reference. With Docker Compose, an optional `.env` file is loaded automatically when present.

## Credentials

Credentials intentionally have no shared defaults. With no router token configured, retain/recall/version endpoints fail closed. Admin capabilities also fail closed unless the required scoped token is configured.

`MEMORY_ROUTER_ALLOW_ANONYMOUS=true` is a development-only override. Explicit boolean values must be `true` or `false`.

## Registry

If `MEMORY_ROUTER_REGISTRY` is absent, the built-in registry contains one framework-neutral writer named `main`. It reads and writes only the `main` bank and uses `source: application`.

`writer_registry.example.json` is intentionally different from the zero-config default. It preserves the historical bundled multi-writer topology (`main`, `ops`, `dev`, `creative`, `personal`, `research`) for deployments that already set:

```text
MEMORY_ROUTER_REGISTRY=/app/writer_registry.example.json
```

Those deployments keep their existing writer/bank behavior across upgrade; the example now uses framework-neutral `source: application` values. New deployments that want the minimal default should leave `MEMORY_ROUTER_REGISTRY` unset. Treat the bundled file as a richer custom-registry example that can be copied and edited for deployment-specific policy.

## Storage

The default is `sqlite:./data/quarantine.db`. Set `QUARANTINE_DATABASE_URL` to an explicit SQLite URL or a PostgreSQL URL when needed.

Cluster mode requires PostgreSQL plus an external/shared admin rate limiter. See [clustered deployment](deployment/clustered.md).

## Tuning

Request bounds, timeouts, rate limits, quarantine capacities, sweep cadence, retention, and other tuning values all have built-in defaults. Explicit invalid values fail startup validation rather than silently falling back.

See [environment variables](reference/environment-variables.md) for the complete list.
