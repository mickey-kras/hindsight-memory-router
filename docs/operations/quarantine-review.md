# Quarantine review

Quarantine decryption happens outside the running router. The router has only the public key.

With the default Compose deployment, private review material is stored in the project-scoped `memory-router-private-key` Compose volume. Compose applies its normal project prefix to the underlying Docker volume, so separate deployments do not share review keys. Back up the volume according to your recovery requirements.

Review flow:

1. Fetch the encrypted item using an authorized read/review client.
2. Supply the private key to the local decrypt CLI over stdin.
3. Inspect the complete decrypted object.
4. Approve, reject, or postpone with the review token.

Example after building the project:

```bash
private-key-command | node dist/src/cli/decryptQuarantine.js encrypted-response.json
```

Approval requires the complete decrypted object unchanged. Modified content fails hash verification.

Review actions claim the item transactionally, call Hindsight without holding a database lock, and then finalize. If an upstream timeout/network failure occurs, verify Hindsight state before retrying because the upstream action may have completed before the response failed.
