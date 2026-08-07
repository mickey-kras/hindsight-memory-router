# Security Policy

## Reporting

Use a private GitHub security advisory.

## Boundaries

- Router token: retain and recall.
- Read token: queue, stats, encrypted items.
- Review token: read plus approve, reject, postpone.
- Cleanup token: cleanup only.
- Legacy admin token: migration only; keep unset afterward.
- Auth fails closed. Tokens are timing-safe and never logged.
- Private quarantine key must never enter the router runtime.
- Approval requires the exact decrypted object and stored hash.
- Hindsight failures expose only stable router error codes and generic messages. Upstream error bodies are discarded after a bounded read; diagnostics contain bounded metadata only.

## Content scanning

The scanner is a deterministic tripwire, not a safety guarantee. It normalizes known Unicode evasions, checks bounded Base64 content, and applies explicit rules. ACLs, quarantine, exact-hash review, and human judgment remain required.

## CI dependency trust

- Aislop is an exact npm dev dependency and runs through local npm scripts; Dependabot updates it.
- Aislop's `adm-zip` dependency is overridden to patched `0.6.0` until its upstream range accepts the fixed release.
- Semgrep uses a versioned image pinned by digest; update the version and digest together.
- GitHub Actions remain pinned by commit SHA.

## Deployment

- `single`: one router process; SQLite or PostgreSQL.
- `cluster`: PostgreSQL plus a real shared admin limiter.
- `MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true` only asserts that limiter exists.

See `docs/DEPLOYMENT_MODES.md`.

## Token migration

1. Add scoped tokens and restart.
2. Migrate and verify clients.
3. Remove the legacy token and restart.

## Runtime

- Private network.
- Do not expose Hindsight directly.
- Run as non-root.
- Keep quarantine storage separate.

## Compatibility

`isAdminAuthorized` now requires a scope and token set. The `adminToken` server option remains as the legacy superuser.

## Non-goal

The router does not secure Hindsight itself.
