# Docker deployment

[Documentation](../README.md) | [Repository](../../README.md)

The repository includes `compose.yaml` for the default single-node deployment.

## Quarantine key material

Generate the RSA quarantine keypair on a trusted admin machine, not on the router host:

```bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out quarantine-private.pem
openssl pkey -in quarantine-private.pem -pubout -out quarantine-public.pem
base64 < quarantine-public.pem | tr -d '\n'
```

Store the private key in a password manager, secret manager, or encrypted offline storage. The router deployment gets only the public key, for example through `.env`:

```text
QUARANTINE_PUBLIC_KEY=<base64-public-key>
```

Never copy, mount, generate, or persist the private key on the router host.

## Start

```bash
docker compose up -d
```

Compose starts one non-root Memory Router service that continues to run.
The router validates the selected wrap provider at startup.
The default `rsa-oaep` must have `QUARANTINE_PUBLIC_KEY`.
`https-sidecar` must have its sidecar settings.
Keep provider settings in `.env`. See [key wrap providers](../security/quarantine.md#pluggable-dek-wrap-providers).

Compose does not generate keys.

Management commands do not use an RSA key.

## Principal registry

Copy `principal_registry.example.json` to `principal_registry.json`.
Customize the principal IDs, token hashes, and bank grants.
The image does not contain a principal registry.
Add this read-only mount in `compose.override.yaml`:

```yaml
services:
  memory-router:
    volumes:
      - ./principal_registry.json:/app/config/principal_registry.json:ro
```

Set `MEMORY_ROUTER_PRINCIPALS=/app/config/principal_registry.json` in `.env`.
Leave `MEMORY_ROUTER_TOKEN` unset.
Make sure uid `10001` can read the file.
`docker compose up -d` automatically loads `compose.override.yaml`.
See [authentication](../security/authentication.md) for token hashing and grants.

## Network exposure and TLS

Compose keeps the router container listener on `0.0.0.0` inside the container but publishes the port on host loopback only: `127.0.0.1:${MEMORY_ROUTER_PORT:-8890}`. Non-container runs bind `127.0.0.1` by default through `MEMORY_ROUTER_HOST`.

The API uses plaintext HTTP.
Anyone who can reach the port can see bearer tokens and memory content.
The router does not decrypt TLS. A TLS terminator must do this.
Before you expose the API beyond the host, put a TLS terminator in front of the router.
Keep the router on loopback or an internal network.

Any TLS terminator works.
Common options are a Caddy or Traefik reverse proxy with automatic certificates, or `tailscale serve` for tailnet-only exposure.
The OpenClaw integrations client must have an `https` router URL.
For this reason, that client must have a terminator.

To expose the router on a LAN or tailnet interface, set the Compose publish address to the address of that interface.
For example, replace `127.0.0.1` with a specific interface address.
For non-container runs, set `MEMORY_ROUTER_HOST` explicitly.
Startup rejects anonymous mode (`MEMORY_ROUTER_ALLOW_ANONYMOUS=true`) on non-loopback binds.

## Container healthcheck

The image includes a readiness healthcheck that uses only Python stdlib.
It checks the configured router port and canonical readiness endpoint.
It disables environment proxy discovery.
For this reason, local readiness never depends on `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` configuration:

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

Normally omit an explicit Compose healthcheck and inherit the image definition. Use the same probe above only when an orchestrator must have an override. Do not add Node, curl, or wget solely for healthchecking.

`/health/ready` checks router quarantine storage and Hindsight health. `/health/live` is the router-only liveness endpoint. `/health` is a readiness alias. Do not use `/ready`. It is a deprecated alias.

## Upgrading from key-init deployments

Preserve the existing keypair before removing the old key volumes. Replacing it with a new keypair makes all existing quarantine items undecryptable.

Extract the existing public key.
Set the returned base64 value as `QUARANTINE_PUBLIC_KEY` in `.env`:

```bash
docker run --rm -v <project>_memory-router-public-key:/k:ro alpine \
  sh -c 'base64 -w0 /k/quarantine-public.pem'
```

If the public-key volume is not available but you kept the matching private key, derive the public key from it again:

```bash
openssl pkey -in quarantine-private.pem -pubout
```

Export the existing private key directly to secure off-host storage. Do not leave a plaintext copy on the router host:

```bash
docker run --rm -v <project>_memory-router-private-key:/k:ro alpine \
  cat /k/quarantine-private.pem > /secure-off-host-storage/quarantine-private.pem
```

If the former Node runtime created the data volume, uid `1000` can still own it. The removed key-init service changed that ownership automatically. Run this command one time before you start the new image:

```bash
docker run --rm -v <project>_memory-router-data:/d alpine chown -R 10001:10001 /d
```

Run the new stack's first startup with `--remove-orphans` so Compose removes the old `quarantine-key-init` container:

```bash
docker compose up -d --remove-orphans
```

After you keep both keys in safe storage and Compose removes the old init container, delete the obsolete key volumes:

```bash
docker volume rm \
  <project>_memory-router-public-key \
  <project>_memory-router-private-key
```

`docker compose down -v` with the new `compose.yaml` does not remove these old volumes, because the project no longer declares them.

## Persistent volume

Compose defines one project-scoped named volume:

- `memory-router-data` -> `/app/data` for SQLite, WAL, and related database files.

Compose applies normal project namespacing. It does not force a global volume name. For this reason, independent deployments on the same Docker host get separate data volumes.

The image runs as `app` (uid and gid `10001`). Make sure that this account can write to each replacement bind mount for `/app/data`.

## Optional overrides

Use `.env` for credentials, the quarantine public key, provider connectivity, or settings that differ from built-in defaults. Start from `.env.example` when necessary.

`MEMORY_ROUTER_PORT` changes both the published host port and the router listener port. For example:

```bash
MEMORY_ROUTER_PORT=9000 docker compose up -d
```

## Published images

GHCR is canonical. Docker Hub is a mirror.

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

`latest` is available for convenience, but it can change. The publish workflow records both registry digests in the job summary and an `image-digests-<commit>` artifact.

Record the running digest after deployment:

```bash
docker inspect --format='{{index .RepoDigests 0}}' <container>
```

Examine a pinned GHCR image with the workflow identity of the repository:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/mickey-kras/hindsight-memory-router/\.github/workflows/publish\.yml@refs/heads/(main|release/[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/mickey-kras/hindsight-memory-router@sha256:<digest>
```

For unified releases started on main, the signer is the reusable `publish.yml` workflow at main.
The image SLSA attestation names the exact frozen commit as the `release-candidate` resolved dependency.
Match that commit to the immutable release tag and `image-digests.txt`.
The source SHA of the workflow stays the `main` dispatch snapshot.

