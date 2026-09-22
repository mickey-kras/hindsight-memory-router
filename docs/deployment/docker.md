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

Compose starts one long-running non-root Memory Router service. The router validates the selected wrap provider at startup: the default `rsa-oaep` requires `QUARANTINE_PUBLIC_KEY`; `https-sidecar` requires its sidecar settings instead. Keep provider settings in `.env` (see [key wrap providers](../security/quarantine.md#pluggable-dek-wrap-providers)). Compose does not generate keys, and management commands do not require an RSA key.

## Principal registry

Copy `principal_registry.example.json` to `principal_registry.json` and customize the principal IDs, token hashes, and bank grants. The image does not contain a principal registry. Add this read-only mount in `compose.override.yaml`:

```yaml
services:
  memory-router:
    volumes:
      - ./principal_registry.json:/app/config/principal_registry.json:ro
```

Set `MEMORY_ROUTER_PRINCIPALS=/app/config/principal_registry.json` in `.env`, leave `MEMORY_ROUTER_TOKEN` unset, and ensure uid `10001` can read the file. `docker compose up -d` automatically loads `compose.override.yaml`. See [authentication](../security/authentication.md) for token hashing and grants.

## Network exposure and TLS

Compose keeps the router container listener on `0.0.0.0` inside the container but publishes the port on host loopback only: `127.0.0.1:${MEMORY_ROUTER_PORT:-8890}`. Non-container runs bind `127.0.0.1` by default via `MEMORY_ROUTER_HOST`.

The API is plaintext HTTP: bearer tokens and memory content are visible to anyone who can reach the port. The router does not terminate TLS itself. Before exposing the API beyond the host, put a TLS terminator in front and keep the router on loopback or an internal network. Any terminator works; common options are a Caddy or Traefik reverse proxy with automatic certificates, or `tailscale serve` for tailnet-only exposure. The OpenClaw integrations client already requires an `https` router URL, so a terminator is mandatory on that path.

To expose the router on a LAN or tailnet interface, set the publish address in Compose (for example a specific interface address instead of `127.0.0.1`) and set `MEMORY_ROUTER_HOST` explicitly for non-container runs. Anonymous mode (`MEMORY_ROUTER_ALLOW_ANONYMOUS=true`) is rejected at startup on non-loopback binds.

## Container healthcheck

The image includes a readiness healthcheck implemented with Python stdlib only. It checks the configured router port and canonical readiness endpoint, and explicitly disables environment proxy discovery so local readiness never depends on `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` configuration:

```yaml
healthcheck:
  test:
    [
      "CMD",
      "python",
      "-c",
      "import os, urllib.request; opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); opener.open(f\"http://127.0.0.1:{os.environ.get('MEMORY_ROUTER_PORT', '8890')}/health/ready\", timeout=2).close()",
    ]
```

Normally omit an explicit Compose healthcheck and inherit the image definition. Use the equivalent probe above only when an orchestrator requires an override. Do not add Node, curl, or wget solely for healthchecking.

`/health/ready` checks router quarantine storage and Hindsight health. `/health/live` remains the router-only liveness endpoint; `/health` is a readiness alias and `/ready` is deprecated.

## Upgrading from key-init deployments

Preserve the existing keypair before removing the old key volumes. Replacing it with a new keypair makes all existing quarantine items undecryptable.

Extract the existing public key and set the returned base64 value as `QUARANTINE_PUBLIC_KEY` in `.env`:

```bash
docker run --rm -v <project>_memory-router-public-key:/k:ro alpine \
  sh -c 'base64 -w0 /k/quarantine-public.pem'
```

If the public-key volume is unavailable but the matching private key was preserved, re-derive the public key from it:

```bash
openssl pkey -in quarantine-private.pem -pubout
```

Export the existing private key directly to secure off-host storage. Do not leave a plaintext copy on the router host:

```bash
docker run --rm -v <project>_memory-router-private-key:/k:ro alpine \
  cat /k/quarantine-private.pem > /secure-off-host-storage/quarantine-private.pem
```

Deployments whose data volume was created by the former Node runtime may still be owned by uid `1000`. The removed key-init service used to migrate that ownership automatically. Run this once before starting the new image:

```bash
docker run --rm -v <project>_memory-router-data:/d alpine chown -R 10001:10001 /d
```

Run the new stack's first startup with `--remove-orphans` so Compose removes the old `quarantine-key-init` container:

```bash
docker compose up -d --remove-orphans
```

After both keys are safely preserved and the old init container is gone, delete the obsolete key volumes:

```bash
docker volume rm \
  <project>_memory-router-public-key \
  <project>_memory-router-private-key
```

`docker compose down -v` with the new `compose.yaml` does not remove these old volumes because they are no longer declared by the project.

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
  --certificate-identity-regexp '^https://github\.com/mickey-kras/hindsight-memory-router/\.github/workflows/publish\.yml@refs/heads/(main|release/[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest>
```

For unified releases started on main, the signer is the reusable `publish.yml` workflow at main.
The image SLSA attestation also names the exact frozen commit as the `release-candidate` resolved
dependency. Match that commit to the immutable release tag and `image-digests.txt`; the workflow's
own source SHA remains the main dispatch snapshot.
