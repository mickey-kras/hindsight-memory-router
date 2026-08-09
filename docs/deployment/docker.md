# Docker deployment

The repository includes `compose.yaml` for the default single-node deployment.

## Quarantine key material

Generate the RSA quarantine keypair on a trusted admin machine, not on the router host:

```bash
umask 077
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

Compose requires `QUARANTINE_PUBLIC_KEY` and starts one long-running non-root Memory Router service. It does not create quarantine keys. The `${QUARANTINE_PUBLIC_KEY:?...}` guard is evaluated by Compose itself, so commands such as `docker compose down`, `ps`, and `logs` also require the variable. Keep `QUARANTINE_PUBLIC_KEY` in `.env` as the canonical Compose location.

## Upgrading from key-init deployments

Preserve the existing keypair before removing the old key volumes. Replacing it with a new keypair makes all existing quarantine items undecryptable.

Extract the existing public key and set the returned base64 value as `QUARANTINE_PUBLIC_KEY` in `.env`:

```bash
docker run --rm -v <project>_memory-router-public-key:/k:ro alpine \
  sh -c 'base64 -w0 /k/quarantine-public.pem'
```

Export `quarantine-private.pem` from `<project>_memory-router-private-key` to trusted off-host storage before deleting the old key volumes. After both keys are safely preserved, delete the old public/private key volumes.

Deployments whose data volume was created by the former Node runtime may still be owned by uid `1000`. The removed key-init service used to migrate that ownership automatically. Run this once before starting the new image:

```bash
docker run --rm -v <project>_memory-router-data:/d alpine chown -R 10001:10001 /d
```

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
