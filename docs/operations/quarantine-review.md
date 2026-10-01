# Quarantine review

[Documentation](../README.md) | [Repository](../../README.md)

Quarantine decryption happens outside the running router. With the default `rsa-oaep` provider, the router has only the public key. For `https-sidecar`, use the configured [key wrap provider](../security/quarantine.md#pluggable-dek-wrap-providers).

For `rsa-oaep`, generate and retain the quarantine private key on a trusted admin machine. Store it in a password manager, secret manager, or encrypted offline storage. Never copy, mount, generate, or persist it on the router host.

## Review flow

1. List pending items with the review token.
2. Fetch the encrypted item with the review token.
3. Retrieve the private key on the trusted admin machine and supply it to the local decrypt CLI over stdin.
4. Inspect the complete decrypted object.
5. Approve, reject, or postpone with the review token.

```bash
private-key-command | memory-router-decrypt-quarantine encrypted-response.json
```

Approval requires the complete decrypted object unchanged. Modified content returns `409 quarantine_hash_mismatch`.

Retain approval preserves the encrypted origin and target bank. Principal retains require the original principal's current `memory.retain` grant for that bank; legacy retains require the writer's bank to remain unchanged. Unknown legacy writers can still be registered before approval. The resolved destination is saved before the upstream write so retries and reconciliation keep the actual bank even if the registry changes.

Pending pre-upgrade `suspicious_content` retains lack verifiable origin and return `409 quarantine_provenance_missing`: reject and resubmit them. Pre-upgrade `unknown_writer` retains keep the registration flow. Completed side effects can still be finalized without replay. No database migration is required.

## Concurrency and interruption recovery

Review actions claim the item in a short transaction, call Hindsight without holding a database lock, then finalize in a second transaction. Concurrent review changes return `409 quarantine_review_changed`.

A definite Hindsight failure restores the previous review state and records `review_interrupted`. Network errors, timeouts and ambiguous server failures keep the item in `review_side_effect_started` to prevent replay.

For an ambiguous outcome:

1. Inspect Hindsight to determine whether the side effect was applied.
2. Fetch the current quarantine item and its snapshot fields.
3. Send `POST /admin/quarantine/items/{id}/reconcile` with `expected_sha256`, `expected_updated_at` and one action:

   | Action | Use when | Result |
   | --- | --- | --- |
   | `confirmed_applied` | You verified the upstream side effect happened. | Finalize without replaying it. |
   | `confirmed_not_applied` | You verified it did not happen. | Move to `postponed`, allowing a normal retry. |

Do not retry an uncertain write without that verification. If the side effect was already checkpointed as completed, a normal retry of the same review action can finalize it without replay.

Startup moves stale `review_in_progress` items to `postponed` without increasing the postpone count. It leaves side-effect checkpoint states untouched. A crash cannot undo a committed Hindsight action.
