# Memory Router

[![ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25%20%28CI--gated%29-brightgreen)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![codeql](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml)
[![aislop](https://badges.scanaislop.com/score/mickey-kras/hindsight-memory-router.svg)](https://scanaislop.com/mickey-kras/hindsight-memory-router)
[![publish + SonarQube](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/publish.yml?query=branch%3Amain)
[![docker image](https://img.shields.io/docker/image-size/mickeykrasilnikov/hindsight-memory-router/latest?label=docker%20image)](https://hub.docker.com/r/mickeykrasilnikov/hindsight-memory-router)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Memory Router is a policy and security boundary for the current OpenClaw Hindsight integration.

```text
OpenClaw (Hindsight plugin) -> Memory Router -> Hindsight
```

Today it:

- accepts the Hindsight-compatible traffic used by the OpenClaw Hindsight plugin;
- proxies the bank-scoped Hindsight HTTP API (banks, memories, documents, entities, mental models, reflect, directives, operations, knowledge base) so agents can use it as a drop-in Hindsight endpoint;
- maps configured writers to Hindsight banks;
- enforces authentication, bounds, quotas, safety scanning, and encrypted quarantine before or after Hindsight calls as appropriate.

Cross-writer, file-transfer, webhook, and metrics endpoints remain denied by policy. Support for additional (non-Hindsight) memory providers is future work and is not implemented in the current runtime.

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
