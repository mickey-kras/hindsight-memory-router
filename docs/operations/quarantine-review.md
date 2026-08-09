# Quarantine review

Quarantine decryption happens outside the running router. The router has only the public key.

Generate and retain the quarantine private key on a trusted admin machine. Store it in a password manager, secret manager, or encrypted offline storage. Never copy, mount, generate, or persist it on the router host.

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

## Concurrency and interruption recovery

Review actions claim the item in a short transaction, call Hindsight without holding a database lock, then finalize in a second transaction. Concurrent review changes return `409 quarantine_review_changed`.

A failed Hindsight call restores the previous review state and records `review_interrupted`. For timeout or network errors, verify Hindsight state before retrying because the upstream action may have completed before the response failed.

On startup, stale `review_in_progress` items are moved to `postponed` without increasing the postpone count. A crash after Hindsight applied an action cannot be rolled back; inspect Hindsight before re-approving.
