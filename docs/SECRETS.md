# Repository secrets

Create these in GitHub:

```text
Settings -> Secrets and variables -> Actions -> New repository secret
```

## Required for Docker Hub publish

```text
DOCKERHUB_USERNAME=<your Docker Hub username>
DOCKERHUB_TOKEN=<Docker Hub access token>
```

Token guidance:

```text
Use a Docker Hub access token, not your account password.
Scope it only for publishing this image if Docker Hub allows scoped tokens for your account.
Rotate it if it is ever pasted into chat, logs, shell history, or a public place.
```

## Built-in GitHub secrets/tokens

No manual setup needed:

```text
GITHUB_TOKEN
```

Used by workflows for:

```text
GHCR publish
GitHub artifact attestation
GitHub Actions permissions
```

## Optional later

```text
FOSSA_API_KEY=<only if FOSSA is enabled later>
```

Not currently required.

## Never add as repository secrets

```text
HINDSIGHT_API_KEY
MEMORY_ROUTER_TOKEN
real production .env values
homelab private IPs or private service tokens
```

Those belong only in the private deployment repo/environment, not this public source repo.
