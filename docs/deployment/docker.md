# Docker deployment

The repository includes `compose.yaml` for the default single-node deployment.

## Quarantine key material

Generate the RSA quarantine keypair on a trusted admin machine, not on the router host:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out quarantine-private.pem
openssl pkey -in quarantine-private.pem -pubout -out quarantine-public.pem
base64 < quarantine-public.pem | tr -d '\n'
```

Store the private key in a password manager, secret manager, or encrypted offline storage. The router deployment receives only the public key, for example through `.env`:

```text
QUARANTINE_PUBLIC_KEY=<base64-public-key>
```

Never copy, mount, generate, or persist the private key on the router host.

## Start

```bash
docker compose up -d
```

Compose starts one long-running non-root Memory Router service. It does not create quarantine keys.

## Persistent volume

Compose defines one project-scoped named volume:

- `memory-router-data` -> `/app/data` for SQLite, WAL, and related database files.

Compose applies normal project namespacing; no global volume name is forced. Independent deployments on the same Docker host therefore receive separate data volumes.

The image runs as `app` (uid/gid `10001`). Ensure any replacement bind mount for `/app/data` is writable by that account.

## Optional overrides

Use `.env` for credentials, the quarantine public key, provider connectivity, or settings that differ from built-in defaults. Start from `.env.example` when needed.

`MEMORY_ROUTER_PORT` changes both the published host port and the router listener port. For example:

```bash
MEMORY_ROUTER_PORT=9000 docker compose up -d
```

## Published images

GHCR is canonical; Docker Hub is a mirror.

```text
ghcr.io/mickey-kras/hindsight-memory-router:<git-sha>
ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest>
docker.io/mickeykrasilnikov/hindsight-memory-router:<git-sha>
docker.io/mickeykrasilnikov/hindsight-memory-router@sha256:<digest>
```

Pin production deployments by digest rather than a mutable tag:

```yaml
services:
  memory-router:
    image: ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest>
```

`latest` remains available for convenience but is mutable. The publish workflow records both registry digests in the job summary and an `image-digests-<commit>` artifact.

Record the running digest after deployment:

```bash
docker inspect --format='{{index .RepoDigests 0}}' <container>
```

Verify a pinned GHCR image with the repository workflow identity:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/mickey-kras/hindsight-memory-router/.github/workflows/publish.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest>
```
