# Architecture

```text
Agent / Application -> Memory Router -> Memory Provider
```

Memory Router is the policy and security boundary. It is not tied to a particular agent framework.

## Responsibilities

On retain and recall, the router:

- authenticates the caller;
- resolves writer policy and allowed memory banks;
- enforces request bounds and rate limits;
- scans content at the policy boundary;
- forwards allowed operations to the configured provider;
- stores unknown or suspicious material in encrypted quarantine.

Hindsight is the only provider implemented today. The architecture keeps product identity separate from Hindsight, but this repository does not yet implement a general provider abstraction.

## Quarantine boundary

Quarantine payloads are encrypted with AES-256-GCM. Each payload key is wrapped with the configured RSA public key. The running router receives the public key only; decryption remains an offline/reviewer responsibility.

See [quarantine security](security/quarantine.md).
