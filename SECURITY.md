# Security Policy

## Reporting

Report vulnerabilities with a private GitHub security advisory. Do not publish exploit details before a fix or mitigation is available.

## Boundaries

- `MEMORY_ROUTER_TOKEN` permits retain and recall only.
- `MEMORY_ROUTER_ADMIN_TOKEN` permits quarantine administration.
- Router and admin authentication fail closed when their token is unset.
- `MEMORY_ROUTER_ALLOW_ANONYMOUS=true` is for local development only.
- Tokens are compared in constant time and are never logged.
- Failed authentication is recorded as a bounded `auth_failed` security event.
- Admin requests are rate-limited per process.
- The router stores only `QUARANTINE_PUBLIC_KEY`.
- `QUARANTINE_PRIVATE_KEY` must stay outside the router runtime.
- Admin approval requires the exact decrypted object and stored SHA-256.

A leaked admin token can read encrypted envelopes and run review actions. It cannot decrypt envelopes or approve modified content.

## Rotation

1. Generate new router and admin tokens.
2. Update the deployment and restart the router.
3. Update OpenClaw and admin clients.
4. Review quarantine events if compromise is suspected.

## Runtime

- Run the router on a private network.
- Do not expose Hindsight directly to untrusted clients.
- Run the container as a non-root user.
- Keep quarantine storage separate from Hindsight application data.

## Non-goal

The router is a policy boundary in front of Hindsight; it does not secure Hindsight itself.
