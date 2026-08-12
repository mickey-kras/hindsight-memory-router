# Architecture

Current supported topology:

```text
OpenClaw (Hindsight plugin) -> Memory Router -> Hindsight
```

Memory Router is the policy and security boundary for this integration. The current runtime is Hindsight-specific and is exercised through the OpenClaw Hindsight plugin; a generic agent/application facade and provider abstraction are not implemented yet.

## Responsibilities

On retain and recall, the router:

- authenticates the OpenClaw Hindsight-plugin request;
- resolves writer policy and allowed Hindsight banks;
- enforces request bounds and rate limits;
- scans content at the policy boundary;
- forwards allowed operations to Hindsight;
- stores unknown or suspicious material in encrypted quarantine.

A broader `Agent / Application -> Memory Router -> Memory Provider` architecture remains a future direction, not the current contract.

For the complete as-built request, quarantine, review, maintenance, CI, and publish flows, see [Runtime interaction map](architecture/runtime-interactions.md). Production-readiness findings are tracked separately in [Production readiness](operations/production-readiness.md).

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
