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
MEMORY_ROUTER_ADMIN_TOKEN is required for admin quarantine routes
QUARANTINE_PRIVATE_KEY is required only for admin read/promote review flow
raw quarantine payloads must not be written to review queue or searchable memory
```

## Runtime expectations

Run the router only on a private network.

Keep the real Hindsight API unavailable to untrusted clients.

Mount quarantine/review storage so the non-root `node` user can write to it. The router validates storage writability on startup and fails fast if permissions are wrong.

## Non-goals

This project does not make Hindsight itself secure. It is a policy facade in front of Hindsight.
