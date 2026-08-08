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
- safely normalizes and bounds untrusted text;
- runs selected OWASP Agent Memory Guard detectors in-process;
- applies Memory Router policy;
- forwards allowed operations to the configured provider;
- stores unknown or suspicious material in encrypted quarantine.

Hindsight is the only provider implemented today. The architecture keeps product identity separate from Hindsight, but this repository does not yet implement a general provider abstraction.

## Threat-inspection pipeline

```text
untrusted memory
  -> deterministic preprocessing/bounds
  -> OWASP Agent Memory Guard detectors
  -> Memory Router policy
  -> provider or encrypted quarantine
```

The same boundary is applied in reverse on recall before provider-returned memory can reach the caller.

Enabled AMG detectors are `prompt_injection`, `sensitive_data`, `tool_abuse`, `privilege_escalation`, and `excessive_autonomy`. The integration uses detector APIs only; AMG does not own application memory, snapshots, persistence, quarantine, or review state.

Deterministic NFKC normalization, invisible-Unicode handling, rolling bounded windows, split-instruction resistance, bounded Base64 inspection, and transformation metadata remain local because they protect input representation and traversal boundaries rather than replacing threat classification.

Stateful AMG detectors such as cross-task contamination, self-reinforcement, rapid change, and size anomaly are intentionally not enabled until the router has the task/key semantics those detectors require. Existing deterministic request-size and rate controls remain authoritative. The optional ML detector is also deferred.

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
