# Memory Router

[![ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25%20%28CI--gated%29-brightgreen)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![codeql](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml)
[![aislop](https://badges.scanaislop.com/score/mickey-kras/hindsight-memory-router.svg)](https://scanaislop.com/mickey-kras/hindsight-memory-router)
[![main validation + SonarQube](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/publish.yml?query=branch%3Amain)
[![docker image](https://img.shields.io/docker/image-size/mickeykrasilnikov/hindsight-memory-router/latest?label=docker%20image)](https://hub.docker.com/r/mickeykrasilnikov/hindsight-memory-router)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Memory Router controls access to [Hindsight](https://github.com/vectorize-io/hindsight) memory banks for OpenClaw and compatible clients. It authenticates callers, limits requests, scans memory content and encrypts unsafe content in quarantine. Use separate write banks for agents. Allow selected shared reads without direct access to Hindsight.

Hindsight is the only supported backend.

Use Memory Router with your own compatible client or the optional [agent integrations](https://github.com/mickey-kras/hindsight-memory-router-integrations). GPU Workload Supervisor is not necessary.

## How it fits together

<a href="https://mickey-kras.github.io/hindsight-memory-router/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/architecture/generated/overview-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/architecture/generated/overview-light.svg">
    <img alt="Agents use Integrations, Memory Router, and Hindsight; Memory Router and its encrypted quarantine are highlighted." src="docs/architecture/generated/overview-light.svg">
  </picture>
</a>

[Explore the architecture and request flows](https://mickey-kras.github.io/hindsight-memory-router/) | [Integrations repository](https://github.com/mickey-kras/hindsight-memory-router-integrations)

## Install and start

Docker Compose, OpenSSL and a reachable Hindsight service are necessary. Download or clone this repository. Run commands from the repository root.

1. On a trusted admin machine, create a quarantine keypair:

   ```sh
   umask 077
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out quarantine-private.pem
   openssl pkey -in quarantine-private.pem -pubout -out quarantine-public.pem
   base64 < quarantine-public.pem | tr -d '\n'
   ```

2. Keep the private key in secure storage outside the router host.
   Put only the base64 public key in the deployment's `.env` as `QUARANTINE_PUBLIC_KEY`.
   Configure `HINDSIGHT_BASE_URL` if Hindsight is not reachable at `http://hindsight:8888` on the Compose network.
   Compose does not start Hindsight.

3. Start the router.
   Check the readiness:

   ```sh
   docker compose up -d
   curl --fail http://localhost:8890/health/ready
   ```

A successful readiness check means router storage and Hindsight are reachable. Compose builds the image and stores SQLite state in a named volume. The published port is loopback-only.

## Connect an agent

Configure [principal credentials and bank grants](docs/security/authentication.md) with the [Compose registry mount](docs/deployment/docker.md#principal-registry).
Then follow [OpenClaw setup](docs/integrations/openclaw.md).
Router and admin operations fail closed until you configure credentials.

The integration must use HTTPS. Add a [TLS terminator](docs/deployment/docker.md#network-exposure-and-tls) before you connect the integration or expose the router beyond the host.
The router accepts plain HTTP upstreams only for private hosts. Set `HINDSIGHT_REQUIRE_SECURE_TRANSPORT=true` to make HTTPS mandatory for every upstream.

## Documentation

- [Getting started](docs/getting-started.md) and [configuration](docs/configuration.md)
- [Docker deployment and upgrades](docs/deployment/docker.md)
- [Quarantine review](docs/operations/quarantine-review.md) and [security](SECURITY.md)
- [All documentation](docs/README.md), including API, architecture, operations and releases

[MIT license](LICENSE) | [Third-party notices](THIRD_PARTY_NOTICES.md).


