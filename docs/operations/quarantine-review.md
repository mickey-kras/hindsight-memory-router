# Quarantine review

[Documentation](../README.md) | [Repository](../../README.md)

Quarantine decryption happens outside the running router. With the default `rsa-oaep` provider, the router has only the public key. For `https-sidecar`, use the configured [key wrap provider](../security/quarantine.md#pluggable-dek-wrap-providers).

For `rsa-oaep`, generate and retain the quarantine private key on a trusted admin machine. Store it in a password manager, secret manager, or encrypted offline storage. Never copy, mount, generate, or persist it on the router host.

## Review flow

1. List pending items with the review token.
2. Fetch the encrypted item with the review token.
3. Retrieve the private key on the trusted admin machine.
4. Supply it to the local decrypt CLI over stdin.
5. Inspect the complete decrypted object.
6. Approve, reject, or postpone with the review token.

```bash
private-key-command | memory-router-decrypt-quarantine encrypted-response.json
```

Approval must have the complete decrypted object with no changes. Modified content returns `409 quarantine_hash_mismatch`.

Retain approval preserves the encrypted origin and target bank.
A principal retain must have the current `memory.retain` grant of the original principal for that bank.
For a legacy retain, the bank of the writer must not change.
Operators can still register unknown legacy writers before approval.
The router saves the resolved destination before the upstream write.
For this reason, retries and reconciliation keep the actual bank even if the registry changes.

Pending pre-upgrade `suspicious_content` retains lack verifiable origin and return `409 quarantine_provenance_missing`.
Reject these retains.
Resubmit them.
Pre-upgrade `unknown_writer` retains keep the registration procedure.
You can still finalize completed side effects without a replay.
A database migration is not necessary.

## Concurrency and interruption recovery

Review actions claim the item in a short transaction.
They call Hindsight without holding a database lock.
They finalize in a second transaction. Concurrent review changes return `409 quarantine_review_changed`.

A definite Hindsight failure restores the previous review state and records `review_interrupted`. Network errors, timeouts and ambiguous server failures keep the item in `review_side_effect_started` to prevent replay.

For an ambiguous outcome:

1. Examine Hindsight to find if the side effect occurred.
2. Fetch the current quarantine item and its snapshot fields.
3. Send `POST /admin/quarantine/items/{id}/reconcile` with `expected_sha256`, `expected_updated_at` and one action:

   | Action | Use when | Result |
   | --- | --- | --- |
   | `confirmed_applied` | You found that the upstream side effect occurred. | Finalize without replaying it. |
   | `confirmed_not_applied` | You found that it did not occur. | Move to `postponed`, allowing a normal retry. |

Do not retry an uncertain write without that verification.
If the side effect has a completed checkpoint, the queue and item endpoint keep it available after the original TTL.
Retry the same review action to finalize it without replay.
Alternatively, use **Finalize approval** or **Finalize rejection** in the console.
Retain approval also must have the exact decrypted object.
A completed checkpoint permits no new reject, postpone, or reconciliation action.

Startup moves stale `review_in_progress` items to `postponed` without increasing the postpone count. It leaves side-effect checkpoint states untouched. A crash cannot undo a committed Hindsight action.

