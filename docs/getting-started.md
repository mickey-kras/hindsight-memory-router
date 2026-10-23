# Getting started

[Documentation](README.md) | [Repository](../README.md)

Use Docker Compose for a single-node router with SQLite. Docker Compose, OpenSSL and a reachable Hindsight service are necessary. Run deployment commands from the repository root.

## Quarantine key

Generate the quarantine keypair on a trusted admin machine, not on the router host:

```bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out quarantine-private.pem
openssl pkey -in quarantine-private.pem -pubout -out quarantine-public.pem
base64 < quarantine-public.pem | tr -d '\n'
```

Store `quarantine-private.pem` in a password manager, secret manager, or encrypted offline storage. Do not copy it to the router host. Put only the base64 public-key value in `.env`:

```text
QUARANTINE_PUBLIC_KEY=<base64-public-key>
```

## Docker Compose

Compose does not start Hindsight. The built-in Hindsight endpoint is `http://hindsight:8888`.
If that Docker service name is not reachable, set `HINDSIGHT_BASE_URL` in `.env` before you start the router.

```bash
docker compose up -d
curl --fail http://localhost:8890/health/ready
```

Compose:

- Must have the quarantine public key.
- Builds the Memory Router image.
- Starts the router in single-node mode.
- Stores SQLite state in a project-scoped `memory-router-data` named volume.
- Never creates, mounts, or stores the quarantine private key.

Configure [principal credentials and grants](security/authentication.md) before you send memory traffic. Router and admin operations fail closed until you configure their credentials. See the [Compose principal registry mount](deployment/docker.md#principal-registry).

## Defaults

Normal startup uses built-in defaults:

- Deployment mode: `single`.
- Quarantine database: `sqlite:./data/quarantine.db`.
- Listener bind and port: `127.0.0.1:8890` (`MEMORY_ROUTER_HOST` and `MEMORY_ROUTER_PORT`).
- One neutral `main` writer that reads and writes only the `main` Hindsight bank.
- Bounded settings for retain, recall, quarantine, timeout, capacity, and retention.

Use `.env.example` as an override reference.

## Next

The integrations must use HTTPS. Configure a [TLS terminator](deployment/docker.md#network-exposure-and-tls) before you connect an agent.
A successful readiness check confirms router storage and Hindsight connectivity. It does not configure credentials or TLS.

- [OpenClaw integration](integrations/openclaw.md)
- [Configuration](configuration.md)
- [Docker deployment](deployment/docker.md)
- [Hindsight upstream](providers/hindsight.md)
- [Authentication](security/authentication.md)

