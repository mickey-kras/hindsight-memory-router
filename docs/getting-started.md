# Getting started

Memory Router sits between an agent/application and Hindsight and applies writer policy, request bounds, authentication, and encrypted quarantine around retain/recall traffic.

## Docker Compose

```bash
docker compose up -d
curl --fail http://localhost:8890/health
```

The first Compose run:

- builds the Memory Router image;
- generates an RSA quarantine keypair if one does not already exist;
- starts the router in single-node mode;
- stores SQLite state in the `memory-router-data` named volume.

No `.env` file is required for startup. Authentication still fails closed: configure a router token before sending retain/recall traffic and scoped admin tokens before using review operations.

The built-in provider endpoint is `http://hindsight:8888`. If Hindsight is not reachable at that Docker service name, set `HINDSIGHT_BASE_URL` in an optional `.env` file.

## Defaults

Normal startup uses built-in defaults:

- deployment mode: `single`;
- quarantine database: `sqlite:./data/quarantine.db`;
- listener port: `8890`;
- built-in framework-neutral writer registry;
- bounded retain/recall, quarantine, timeout, capacity, and retention settings.

Use `.env.example` only as an override reference.

## Next

- [Configuration](configuration.md)
- [Docker deployment](deployment/docker.md)
- [Hindsight provider](providers/hindsight.md)
- [Authentication](security/authentication.md)
