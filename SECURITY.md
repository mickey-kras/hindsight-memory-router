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
deterministic safety filters
review queue handling
Hindsight API forwarding
container image publishing
```

## Non-goals

This project does not make Hindsight itself secure. It is a policy facade in front of Hindsight.

Run it only on a private network and keep the real Hindsight API unavailable to untrusted clients.
