# Memory Router

[![ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![codeql](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Memory Router is an agent- and framework-neutral policy boundary between an application and its memory provider.

```text
Agent / Application -> Memory Router -> Memory Provider
```

It has two goals:

- decouple agents and applications from provider-specific memory access;
- enforce a security and policy boundary around memory retain and recall.

Hindsight is the currently supported memory provider. Provider abstraction is not implemented yet.

## Quick start

The default deployment is single-node with embedded SQLite. Generate the quarantine keypair on a trusted admin machine, keep the private key there, and provide only the public key to the router deployment.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out quarantine-private.pem
openssl pkey -in quarantine-private.pem -pubout -out quarantine-public.pem
base64 < quarantine-public.pem | tr -d '\n'
```

Store `quarantine-private.pem` in your password manager, secret manager, or encrypted offline storage. Put the base64 public-key value in `.env` as `QUARANTINE_PUBLIC_KEY`, then start the router:

```bash
docker compose up -d
curl --fail http://localhost:8890/health
```

Router and admin capabilities remain fail-closed until their credentials are configured. The default Hindsight URL is `http://hindsight:8888`; attach a Hindsight service on the same Docker network or override that endpoint for your deployment.

## Documentation

- [Getting started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [Hindsight provider](docs/providers/hindsight.md)
- [Docker deployment](docs/deployment/docker.md)
- [Security](docs/security/quarantine.md)
- [Environment variable reference](docs/reference/environment-variables.md)
- [API reference](docs/reference/api.md)

## License

MIT
