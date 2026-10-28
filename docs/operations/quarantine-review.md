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

## Provider-wrapped and hardware-key review

The review console uses a separate trusted local agent for provider-wrapped envelopes.
The reviewer runs the agent on their workstation.
Native RSA envelopes still work with an imported PKCS8 key.
Select **Use a hardware-backed key via local review agent** to use a hardware-held RSA key.

The agent is not a router endpoint.
It listens only on `127.0.0.1:8765`.
The agent uses port `8765` to match the console and its Content Security Policy.

It checks the exact console origin and a random access credential.
The agent unwraps the DEK and verifies AES-256-GCM, AAD, SHA-256, and metadata.

It sends only the verified object back to the console.
The private key and PIN stay outside the browser and router.
The router verifies the stored SHA-256 again during approval.

On the **trusted reviewer workstation**, install the `review` extra and create an owner-only credential:

```bash
umask 077
openssl rand -hex 32 > review-agent-credential
python -m pip install 'hindsight-memory-router[review]'
memory-router-review-agent \
  --origin https://your-review-console.example \
  --reviewer your-reviewer-id \
  --credential-file review-agent-credential \
  --audit-db review-agent-audit.sqlite3 \
  --pkcs11-module /path/to/your/pkcs11-library.so \
  --pkcs11-token your-token-label \
  --pkcs11-key your-rsa-private-key-label
```

The agent prompts for the PIN on its terminal.
The token enforces its PIN and touch policy.
For keys with `CKA_ALWAYS_AUTHENTICATE`, the agent also supplies the PIN for each unwrap operation.

Paste the *local agent credential* into the console's agent field.
Do not use the router token or token PIN in this field.

The credential stays in that browser tab. The console clears it when you change items.
Set `--origin` to the exact console origin (scheme, hostname, and port).
The console uses a fixed loopback address and cannot send envelopes to arbitrary hosts.

For a hosted console, allow access to loopback under your browser's local-network policy.

The agent accepts JSON requests up to 2,097,152 bytes by default.
Use `--max-request-bytes` to set a positive integer limit in bytes.

Set the agent limit above the router's `QUARANTINE_MAX_ITEM_BYTES`.
The router counts the bytes in the encrypted envelope.
This count includes base64 encoding and metadata.

The agent also receives the outer `{"envelope":...}` JSON wrapper.
With compact serialization, this wrapper adds 13 bytes.
Serialization whitespace adds more bytes.

Measure the complete serialized request before you set a tight limit.
For larger router items, increase the agent limit.
Make sure your workstation has enough memory for this limit.

For an external provider, use `--external-provider ENTRY_POINT`.
You can use this option with or without the PKCS#11 options.
Install the provider **only in the reviewer environment**.
Register its zero-argument factory under Python entry-point group `hindsight_memory_router.review_unwrap`.
The factory returns an object with:

- `identity: ReviewProviderId(key_wrap, name, version)` matching the envelope exactly (for native RSA: `ReviewProviderId("RSA-OAEP-SHA256")`).
- `unwrap(wrapped_dek: bytes, envelope: Mapping[str, Any]) -> bytes`, returning a 32-byte DEK. The agent validates the envelope before it calls the provider. The agent checks the decrypted object after unwrapping.

An independent package can register `my-review-provider = "my_package.review:make_provider"`.
Enable it with `--external-provider my-review-provider`.
Keep provider packages and credentials outside the router deployment.
The registry rejects duplicate identities and never falls back to a different key or provider.

The local SQLite audit keeps at most 1,000 events.
It reserves separate rolling quotas of 100 unauthorized events and 900 authenticated
`verified` or `failed` events. Unauthenticated requests, including malformed ones,
cannot evict authenticated review history.
Each event contains a timestamp, configured reviewer, validated quarantine ID, and outcome.
Outcomes are `verified`, `failed`, or `unauthorized`.
The audit never stores plaintext, keys, PINs, credentials, or request bodies.
Use an owner-only workstation directory.
The router's authenticated approval and rejection audit remains unchanged.

### Manual PKCS#11/PIV smoke test

1. Create a **synthetic** native RSA envelope with the token's public key. Check the envelope's `key_wrap` and confirm that it has no `provider` metadata. Do not use production evidence.
2. Start the agent with the PKCS#11 module, token label, key label, credential, and console origin. Enter the token PIN.
3. Select the synthetic item. Enable **Use a hardware-backed key**. Paste the agent credential. Click **Decrypt with local agent**.
4. Check the token touch prompt, decrypted object, and `verified` audit record.
5. Retry with an incorrect key or denied PIN or touch. Confirm failure and a `failed` audit event. Approval must stay disabled.
6. Change the ciphertext, AAD metadata, and digest in separate tests. Confirm the console shows no plaintext and approval stays disabled.
7. Keep the private key inside the hardware token. Do not copy it to the router.

Automated tests use a simulated PKCS#11 driver and an independent mock provider.
Confirm real PIN and touch behavior with the manual test.

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

