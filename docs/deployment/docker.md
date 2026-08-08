# Docker deployment

The repository includes `compose.yaml` for the default single-node deployment.

```bash
docker compose up -d
```

Compose builds one Memory Router image and uses it for:

- `quarantine-key-init`: a short-lived, idempotent key bootstrap with networking disabled;
- `memory-router`: the long-running non-root router process.

## Persistent volumes

Compose defines three project-scoped named volumes:

- `memory-router-data` -> `/app/data` for SQLite, WAL, and related database files;
- `memory-router-public-key` for the public encryption key;
- `memory-router-private-key` for review key material.

Compose applies normal project namespacing; no global volume names are forced. Independent deployments on the same Docker host therefore receive separate data and key volumes. The underlying Docker volume names are derived from the Compose project name rather than fixed by this repository.

The router mounts the public-key volume read-only and does not mount the private-key volume. The initializer is the only service that mounts the private-key volume, and it runs with `network_mode: none`. The image runs as `app` (uid/gid `10001`). On startup, the root key-init helper recursively changes `/app/data` ownership to `app:app`; this also migrates existing Compose data volumes created by the former Node image, which used uid `1000`.

The review key file is stored in the project-scoped private-key volume and is needed only for authorized quarantine review. Back up that volume according to your recovery policy; losing it makes existing quarantine evidence undecryptable.

## Optional overrides

No `.env` file is required. If present, Compose loads `.env` as an override file. Start from `.env.example` only when tuning behavior or configuring credentials/provider connectivity.

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
