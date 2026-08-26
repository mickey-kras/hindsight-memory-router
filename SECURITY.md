# Security Policy

## Reporting

Use a private GitHub security advisory.

## Boundaries

- Router token: authenticates a trusted retain/recall client, not an individual writer identity.
- `writer_id` is selected by that authenticated client and is used for routing/policy; it is not a per-writer credential. Do not give one shared router token to mutually untrusted agents if writer-bank isolation is a security requirement.
- Registry bank names and writer read/write topology are deployment policy. The router no longer hardcodes a `main`-cannot-read-`research` invariant; deployments that require that isolation must express and validate it in their registry/governance rather than relying on a built-in bank-name special case.
- Read token: queue, stats, encrypted items.
- Review token: read plus approve, reject, postpone.
- Cleanup token: cleanup only.
- Legacy admin token: migration only; keep unset afterward.
- Auth fails closed. Tokens are timing-safe and never logged.
- A recognized admin token used outside its allowed scope returns the same generic 401 as other authorization failures, but is intentionally not charged to the bad-token throttle or auth-failure audit. This prevents a valid mis-scoped client from exhausting the shared authentication-failure budget.
- Private quarantine key must never enter the router runtime.
- Approval requires the exact decrypted object and stored hash. Review claims also pin the row `sha256`/`updated_at` snapshot under the database row lock before committing a decision.
- Hindsight failures expose only stable router error codes and generic messages. Upstream error bodies are discarded without inspection; diagnostics contain fixed bounded metadata only.

## Content scanning

The scanner is a deterministic tripwire, not a safety guarantee. It recursively scans string keys and values across retain, recall, facade, query, and provider-response surfaces; normalizes known Unicode evasions; checks bounded Base64 content; and applies explicit rules. ACLs, quarantine, exact-hash review, and human judgment remain required.

Base64 reassembly is deliberately bounded so attacker-controlled 1 MiB requests cannot create unbounded synchronous work. Split candidates are limited to 64 live candidates, 256 Base64-like fields, 512 KiB of candidate-building work per active candidate set, and an encoded candidate size corresponding to `MAX_BASE64_DECODED_BYTES`; at most two Base64-looking decoy fragments may be skipped. Whitespace/punctuation-separated chunks, unpadded standard Base64, dictionary keys, and traversal-adjacent key/value fragments are considered. Ambiguous work may reset before any credible candidate appears; after credibility is established, exhaustion is sticky and fails closed. Exhausting a hard size/field budget or a credible combinatorial budget fails closed with `split_base64_limit`.

Cross-fragment instruction matching retains a 512-byte normalized suffix, tries compact or spaced reconstruction independently at each of up to four adjacent boundaries, skips any two intervening fields in a five-field span, and fails closed after 8,192 reconstructed windows per value-only, key-only, or traversal-order group. A sufficiently large whitespace gap or more than two decoys can separate fragments; request limits, ACLs, quarantine, and review remain necessary controls.

Instruction rules intentionally use phrase and word boundaries to limit false positives. Related nouns or inflections such as `system prompts`, `new instruction`, and `exfiltrating` are not standalone findings. Split scans intentionally exclude `system prompt`, `developer message`, and `new instructions` unless another detector or a complete field matches them. Bare `api`/`key` and `private`/`key` field-name pairs are suppressed; surrounding contextual text is not.

Known tripwire limits: the confusable table is not exhaustive for IPA lookalikes; supplementary mappings cover reported gaps in the pinned table, including Unicode 16/17 outlined letters and digits. Base64url is not decoded. Padded and unpadded standard Base64 are decoded through one nested encoded layer. Whitespace-separated Base64 is considered only when its chunks are at most seven characters. These are not security boundaries.

Confusable alternatives are capped at 32 per scanned field/window; exhaustion fails closed with `confusable_variant_limit`. One confusable-heavy field can therefore suppress a whole shared recall/facade response. Latin, Cyrillic, or Greek letters with no ASCII skeleton fail closed when embedded next to ASCII word characters. Default-Ignorable characters and mark runs between ASCII word/separator characters block as `invisible_unicode`. Ordinary script marks such as Indic vowel signs, Arabic harakat, and Hebrew niqqud are preserved.

Retain, recall, and query scans have a five-second post-phase deadline; it is a tripwire rather than a preemptive wall-time timeout. Individual strings are capped at 1 MiB, and fields containing more than 65,536 non-ASCII code points fail closed before Unicode canonicalization. Query scans inspect at most 256 pairs. Other direct/rolling field and window limits fail closed. Authenticated requests consume their retain/recall quota before scanning; unknown writers and cheap structural failures do not.

Hard Base64 evidence (`=`, `+`, or `/`) fails closed on invalid encoding or invalid UTF-8. Mixed-case-plus-digit tokens are only decode-and-scan hints so ordinary identifiers such as device/model names are not blocked. A weak-signal token that validly decodes to non-UTF-8 binary is ignored unless hard Base64 evidence is also present.

Split-Base64 candidate limits are deliberately sensitive: several short Base64-like fields or a long Base64-alphabet-only token/blob can return `split_base64_limit` and quarantine otherwise benign content.

Reviewed recall approvals pin stable memory identity/content (`id` + `text`). When that digest still matches, the approved `id`/`text` is not rescanned; volatile returned fields continue to be rescanned on every recall. A newly unsafe extra/metadata field suppresses the result and reopens review.

## Quarantine lifecycle

- Stale `review_in_progress` claims are recovered both by the periodic sweep and on demand for approve, reject, and postpone actions. Disabling the periodic sweep does not make stale review claims permanent.
- A stale review claim that has also expired is deleted/expired transactionally during on-demand recovery rather than being restored to a permanently stuck `review_in_progress` row.
- Non-idempotent admin operations (`retain` approval and recalled-memory rejection) persist `review_side_effect_started` before calling Hindsight. That state is never stale-auto-reopened or re-quarantined: after an ambiguous upstream/DB failure, retries fail closed instead of repeating a potentially successful retain/invalidate. Reconcile such a row manually before taking another action.
- `reviewed_allowed` and `reviewed_blocked` rows are decision state and are intentionally retained; admin cleanup does not purge them. A reviewed-allowed memory is reopened when stable content changes or when newly unsafe recalled extras require review.
- Oversized suspicious recalled content is not retained in full. The router records a bounded quarantine security-event placeholder containing source identity, stable digest, and scanner findings without the oversized payload.
- An `unknown_writer` retain that is unsafe cannot be directly approved after merely registering the writer. Resubmit it after registration so the normal retain scanner classifies it as `suspicious_content`, then review that quarantine item.

## CI dependency trust

- `confusables==1.2.0` is an explicit maintenance exception: the scanner needs UTS #39-style skeleton folding, available alternatives have similar maintenance risk, and the dependency is exact-pinned with verified hashes. Revisit the exception when a maintained compatible implementation is available or the package needs an unreviewed data/code update.
- Pebble 5.2.1's LGPL-3.0 use is accepted for worker isolation; published images include its notice, LGPL-3.0/GPL-3.0 text, and upstream source URL.
- Aislop is an exact npm dev dependency and runs through local npm scripts; Dependabot updates it.
- Semgrep uses a versioned image pinned by digest; update the version and digest together.
- GitHub Actions remain pinned by commit SHA.
- Dependabot auto-merge is allowlisted to semantic-version patch and minor updates only. Major and unclassified/non-semver updates require human review.

## Deployment

- `single`: one router process; SQLite or PostgreSQL.
- `cluster`: PostgreSQL plus a real shared admin limiter.
- The built-in admin request limiter remains per-process, including with PostgreSQL. Cluster deployments must enforce the shared admin limit externally; `MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true` only asserts that such a limiter exists.

See `docs/DEPLOYMENT_MODES.md`.

## Token migration

1. Add scoped tokens and restart.
2. Migrate and verify clients.
3. Remove the legacy token and restart.

## Runtime

- Private network.
- Do not expose Hindsight directly.
- Run as non-root.
- Keep quarantine storage separate.

## Compatibility

The Python runtime authorizes admin requests with scoped tokens configured through `MEMORY_ROUTER_ADMIN_READ_TOKEN`, `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`, and `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`. `MEMORY_ROUTER_ADMIN_TOKEN` remains a temporary legacy superuser environment variable for migration only.

## Non-goal

The router does not secure Hindsight itself.
