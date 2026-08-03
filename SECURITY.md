# Security Policy

## Reporting

Please open a private security advisory in GitHub if possible.

Do not publish exploit details publicly before there is a fix or mitigation.

## Scope

Security-sensitive areas:

```text
writer identity
bank routing
recall ACL
router/admin token separation
encrypted quarantine object storage
private-key-only admin decrypt flow
safe review queue records
Hindsight API forwarding
non-root container runtime
container image publishing
```

## Boundaries

```text
MEMORY_ROUTER_TOKEN can retain/recall through the facade
MEMORY_ROUTER_TOKEN cannot read/decrypt/approve quarantine
router auth fails closed when MEMORY_ROUTER_TOKEN is unset
MEMORY_ROUTER_ALLOW_ANONYMOUS=true is a dev-only opt-in to anonymous router access
MEMORY_ROUTER_ADMIN_TOKEN is required for admin quarantine routes
admin routes are rate limited per process (429 admin_rate_limited)
tokens are compared in constant time and are never logged
failed authentication is audited as auth_failed security events
QUARANTINE_PRIVATE_KEY is required only for admin read/promote review flow
a leaked admin token cannot approve forged content or decrypt envelopes
raw quarantine payloads must not be written to review queue or searchable memory
```

Token rotation: replace `MEMORY_ROUTER_TOKEN`/`MEMORY_ROUTER_ADMIN_TOKEN` with new random values, restart the router, and update the OpenClaw plugin config and admin clients. Old tokens stop working at restart. Rotate the admin token immediately if quarantine metadata, envelopes, or review actions may have been exposed.

## Runtime expectations

Run the router only on a private network.

Keep the real Hindsight API unavailable to untrusted clients.

Mount quarantine/review storage so the non-root `node` user can write to it. The router validates storage writability on startup and fails fast if permissions are wrong.

## Non-goals

This project does not make Hindsight itself secure. It is a policy facade in front of Hindsight.
