# Getting started

Memory Router currently sits between the OpenClaw Hindsight plugin and Hindsight:

```text
OpenClaw (Hindsight plugin) -> Memory Router -> Hindsight
```

It applies writer policy, request bounds, authentication, quotas, safety scanning, and encrypted quarantine around the retain/recall traffic used by that integration. A generic agent/application facade is not implemented yet.

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

```bash
docker compose up -d
curl --fail http://localhost:8890/health/ready
```

Compose:

- requires the quarantine public key;
- builds the Memory Router image;
- starts the router in single-node mode;
- stores SQLite state in a project-scoped `memory-router-data` named volume;
- never creates, mounts, or stores the quarantine private key.

Authentication still fails closed: configure a router token before sending retain/recall traffic and scoped admin tokens before using review operations.

The built-in Hindsight endpoint is `http://hindsight:8888`. If Hindsight is not reachable at that Docker service name, set `HINDSIGHT_BASE_URL` in `.env`.

## Defaults

Normal startup uses built-in defaults:

- deployment mode: `single`;
- quarantine database: `sqlite:./data/quarantine.db`;
- listener port: `8890`;
- one neutral `main` writer that reads and writes only the `main` Hindsight bank;
- bounded retain/recall, quarantine, timeout, capacity, and retention settings.

Use `.env.example` as an override reference.

## Next

- [OpenClaw integration](integrations/openclaw.md)
- [Configuration](configuration.md)
- [Docker deployment](deployment/docker.md)
- [Hindsight upstream](providers/hindsight.md)
- [Authentication](security/authentication.md)
