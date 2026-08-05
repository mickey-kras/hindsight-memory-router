# Security Policy

## Reporting

Report vulnerabilities with a private GitHub security advisory. Do not publish exploit details before a fix or mitigation is available.

## Boundaries

- `MEMORY_ROUTER_TOKEN` permits retain and recall only.
- `MEMORY_ROUTER_ADMIN_READ_TOKEN` permits queue, statistics, and encrypted-item reads only.
- `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN` permits reads plus approve, reject, and postpone.
- `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN` permits cleanup only.
- `MEMORY_ROUTER_ADMIN_TOKEN` is a legacy migration superuser and should remain unset after scoped-client migration.
- Router and admin authentication fail closed when no effective token authorizes the requested capability.
- `MEMORY_ROUTER_ALLOW_ANONYMOUS=true` is for local development only.
- Tokens are compared in constant time and are never logged.
- Failed authentication is recorded as a bounded `auth_failed` security event.
- Admin requests are rate-limited per process.
- The router stores only `QUARANTINE_PUBLIC_KEY`.
- `QUARANTINE_PRIVATE_KEY` must stay outside the router runtime.
- Admin approval requires the exact decrypted object and stored SHA-256.

A leaked read token cannot mutate quarantine state. A leaked cleanup token cannot inspect encrypted envelopes or make review decisions. A leaked review token can read encrypted envelopes and make review decisions but cannot execute bulk cleanup. No admin credential can decrypt envelopes or approve modified content.

## Rotation and migration

1. Generate independent router, read, review, and cleanup tokens.
2. Configure scoped admin tokens and restart the router while temporarily retaining the legacy token.
3. Migrate each client to the least-privilege token it requires.
4. Confirm scoped clients operate correctly.
5. Unset `MEMORY_ROUTER_ADMIN_TOKEN` and restart the router.
6. Rotate any scoped credential independently when needed.
7. Review quarantine events if compromise is suspected.

A startup warning is emitted while the legacy migration superuser remains active.

## Runtime

- Run the router on a private network.
- Do not expose Hindsight directly to untrusted clients.
- Run the container as a non-root user.
- Keep quarantine storage separate from Hindsight application data.

## Compatibility

The exported `isAdminAuthorized` helper now requires an admin capability and token set rather than one optional token. Programmatic embedders must update direct calls. The `adminToken` server option remains supported as the legacy migration superuser.

## Non-goal

The router is a policy boundary in front of Hindsight; it does not secure Hindsight itself.
