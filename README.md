# Memory Router

[![ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![codeql](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Memory Router is a policy and security boundary for the current OpenClaw Hindsight integration.

```text
OpenClaw (Hindsight plugin) -> Memory Router -> Hindsight
```

Today it:

- accepts the Hindsight-compatible retain/recall traffic used by the OpenClaw Hindsight plugin;
- maps configured writers to Hindsight banks;
- enforces authentication, bounds, quotas, safety scanning, and encrypted quarantine before or after Hindsight calls as appropriate.

Memory Router is not yet a generic agent/application memory facade. Support for additional clients or memory providers is future work and is not implemented in the current runtime.

## Quick start

The default deployment is single-node with embedded SQLite. Generate the quarantine keypair on a trusted admin machine, keep the private key there, and provide only the public key to the router deployment.

```bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out quarantine-private.pem
openssl pkey -in quarantine-private.pem -pubout -out quarantine-public.pem
base64 < quarantine-public.pem | tr -d '\n'
```

Store `quarantine-private.pem` in your password manager, secret manager, or encrypted offline storage. Put the base64 public-key value in `.env` as `QUARANTINE_PUBLIC_KEY`, then start the router:

```bash
docker compose up -d
curl --fail http://localhost:8890/health/ready
```

Router and admin capabilities remain fail-closed until their credentials are configured. The default Hindsight URL is `http://hindsight:8888`; attach a Hindsight service on the same Docker network or override that endpoint for your deployment.

## Documentation

- [Getting started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [Hindsight upstream](docs/providers/hindsight.md)
- [OpenClaw integration](docs/integrations/openclaw.md)
- [Docker deployment](docs/deployment/docker.md)
- [Security](docs/security/quarantine.md)
- [Environment variable reference](docs/reference/environment-variables.md)
- [API reference](docs/reference/api.md)

## License

MIT
