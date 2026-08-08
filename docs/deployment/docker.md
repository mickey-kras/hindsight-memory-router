# Docker deployment

The repository includes `compose.yaml` for the default single-node deployment.

```bash
docker compose up -d
```

Compose builds one Memory Router image and uses it for:

- `quarantine-key-init`: a short-lived, idempotent key bootstrap;
- `memory-router`: the long-running non-root router process.

## Persistent volumes

- `memory-router-data` -> `/app/data` for SQLite, WAL, and related database files;
- `memory-router-quarantine-public-key` for the RSA public key;
- `memory-router-quarantine-private-key` for the private review key.

The router mounts the public-key volume read-only and does not mount the private-key volume. The image owns `/app/data` as the non-root `node` user so SQLite and WAL files remain writable inside the named volume.

The private key is stored at `quarantine-private.pem` inside the Docker volume named `memory-router-quarantine-private-key`. It is needed only for authorized quarantine review/decryption. Back it up according to your recovery policy; losing it makes existing quarantine evidence undecryptable.

## Optional overrides

No `.env` file is required. If present, Compose loads `.env` as an override file. Start from `.env.example` only when tuning behavior or configuring credentials/provider connectivity.

## Image verification

Production deployments should pin the published image by digest. GHCR is canonical and Docker Hub is a mirror. The publish workflow records registry digests and signs published images with the repository workflow identity.
