# Quarantine review

Quarantine decryption happens outside the running router. The router has only the public key.

With the default Compose deployment, private review material is stored in the project-scoped `memory-router-private-key` Compose volume. Compose applies its normal project prefix to the underlying Docker volume, so separate deployments do not share review keys. Back up the volume according to your recovery requirements.

## Review flow

1. List pending items with the review token.
2. Fetch the encrypted item with the review token.
3. Supply the private key to the local decrypt CLI over stdin and inspect the complete decrypted object.
4. Approve, reject, or postpone with the review token.

Example from a development checkout:

```bash
uv sync --frozen
private-key-command | uv run python -m memory_router.cli.decrypt_quarantine encrypted-response.json
```

Approval requires the complete decrypted object unchanged. Modified content returns `409 quarantine_hash_mismatch`.

## Concurrency and interruption recovery

Review actions claim the item in a short transaction, call Hindsight without holding a database lock, then finalize in a second transaction. Concurrent review changes return `409 quarantine_review_changed`.

A failed Hindsight call restores the previous review state and records `review_interrupted`. For timeout or network errors, verify Hindsight state before retrying because the upstream action may have completed before the response failed.

On startup, stale `review_in_progress` items are moved to `postponed` without increasing the postpone count. A crash after Hindsight applied an action cannot be rolled back; inspect Hindsight before re-approving.
