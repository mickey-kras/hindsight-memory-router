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

## Routing behavior

Retain:

```text
known writer + clean content -> assigned Hindsight bank
unknown writer               -> encrypted quarantine
suspicious content           -> encrypted quarantine
```

Recall:

```text
known writer                 -> allowed read banks only
unknown writer               -> empty results + quarantine item
suspicious query             -> empty results + quarantine item
suspicious recalled result   -> suppressed + quarantine item
reviewed allowed result      -> returned while content is unchanged
reviewed blocked result      -> suppressed and invalidated
```

Recall availability rules:

- A typed Hindsight failure affects only that read bank.
- If all read banks fail, recall returns empty results.
- `429`, `507`, and `quarantine_request_in_review` prevent the affected suspicious result from being returned but do not fail recall.
- Unexpected application or database errors still propagate.
- Degradation logs contain structured error codes, not upstream response text.
- Retain never degrades when quarantine is unavailable.

There is no Hindsight quarantine bank.

## Quarantine boundary

Quarantine payloads are encrypted with AES-256-GCM. Each payload key is wrapped with the configured RSA public key. The running router receives the public key only; decryption remains an offline/reviewer responsibility.

See [quarantine security](security/quarantine.md).
