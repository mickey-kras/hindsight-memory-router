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

## Required for SonarQube

```text
SONAR_TOKEN=<project analysis token>
SONAR_HOST_URL=<SonarQube base URL reachable from the GitHub runner>
```

The SonarQube project must already exist with key `hindsight-memory-router`.

## Private SonarQube access

```text
TAILSCALE_OAUTH_CLIENT_ID=<OAuth client ID>
TAILSCALE_AUDIENCE=<OIDC audience>
```

The current workflow uses Tailscale. Replace that connection step if your SonarQube network uses another method.

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
production .env values
private-network addresses or service tokens
```

Keep them in your private deployment environment.
