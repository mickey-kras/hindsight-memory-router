# Memory Router documentation

[Repository](../README.md)

Start with [Getting started](getting-started.md), then configure [authentication and bank grants](security/authentication.md) before connecting an agent.

## Set up

- [Getting started](getting-started.md): keys, Compose and first health check
- [Configuration](configuration.md) and [environment variables](reference/environment-variables.md)
- [Docker and upgrades](deployment/docker.md), [SQLite](deployment/sqlite.md), [PostgreSQL](deployment/postgresql.md) and [clustered deployment](deployment/clustered.md)
- [Deployment modes](DEPLOYMENT_MODES.md) and [Hindsight connection](providers/hindsight.md)
- [OpenClaw integration](integrations/openclaw.md)

## Operate and secure

- [Authentication and grants](security/authentication.md)
- [Quarantine encryption, capacity and retention](security/quarantine.md)
- [Review quarantined content](operations/quarantine-review.md)
- [Clean up records](operations/cleanup.md) and [migrate legacy quarantine](operations/legacy-migration.md)
- [Logging](operations/logging.md) and [production-readiness findings](operations/production-readiness.md)
- [Quarantine console](../ui/README.md) and [security policy](../SECURITY.md)

## Understand and maintain

- [Architecture](architecture.md) and [C4 diagrams](architecture/README.md)
- [API reference](reference/api.md) and [OpenAPI / Swagger UI](OPENAPI.md)
- [Integration tests](../tests/integration/README.md) and [branching](../.github/BRANCHING.md)
- [Releasing](RELEASING.md), [repository secrets](SECRETS.md), [dependency updates](dependabot.md) and [main pipeline failures](ci-failures.md)
- [Third-party notices](../THIRD_PARTY_NOTICES.md) and [license](../LICENSE)
