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

The scanner is a tripwire, not a security boundary. It scans string keys and values in retain, recall, facade, query, and Hindsight responses. It normalizes Unicode, checks bounded standard Base64, and applies explicit rules. Keep ACLs, request limits, quarantine, exact-hash review, and human review.

### Fail-closed limits

| Scope | Limit |
| --- | --- |
| Retain, recall, facade request | 5-second cooperative deadline |
| Query | 256 pairs; 10-second deadline; 32,768 rolling windows total and skip windows per group |
| Facade response | 256 KiB; 8,192 fields; 30-second deadline |
| Other rolling or skip scans | 8,192 windows per value, key, or traversal group |
| String | 1 MiB; 65,536 non-ASCII code points |
| Confusable variants | 32 per field or window |
| Split Base64 | 64 candidates; 256 fragments; 512 KiB candidate work; two skipped fragments |

Deadlines are checked between scan units; they are not preemptive. Authenticated requests consume quota before scanning. Unknown writers and cheap structural failures do not.

### Base64

Split reconstruction covers whitespace-, punctuation-, and label-separated chunks, serialized JSON values, dictionary keys, and adjacent key/value fragments. It can skip two fragments within a five-field span. Limit exhaustion returns `split_base64_limit`; this can quarantine benign Base64-like content.

Hard Base64 evidence (`=`, `+`, or `/`) fails closed on invalid encoding or UTF-8. Mixed-case tokens with digits are weak hints, so valid binary identifiers are ignored. Padded and unpadded standard Base64 are decoded through one nested layer. Base64url is not decoded.

### Unicode and instruction rules

Scanning uses NFKC, semantic folds, Latin-diacritic removal, and vendored Unicode UTS #39 17.0.0 ASCII skeletons. Non-ASCII skeletons are preserved. Invisible/control Unicode fails closed; script marks used by Indic, Arabic, and Hebrew text are preserved.

Phrase and word boundaries reduce false positives. Related inflections may not match. Split scans exclude `system prompt`, `developer message`, and `new instructions` unless another detector or a complete field matches. Separate bare `api`/`key` and `private`/`key` fields are suppressed when only version tokens sit between them.

Reviewed recall approvals pin stable memory identity/content (`id` + `text`). When that digest still matches, the approved `id`/`text` is not rescanned; volatile returned fields continue to be rescanned on every recall. A newly unsafe extra/metadata field suppresses the result and reopens review.

## Quarantine lifecycle

- Stale `review_in_progress` claims are recovered both by the periodic sweep and on demand for approve, reject, and postpone actions. Disabling the periodic sweep does not make stale review claims permanent.
- A stale review claim that has also expired is deleted/expired transactionally during on-demand recovery rather than being restored to a permanently stuck `review_in_progress` row.
- Non-idempotent admin operations (`retain` approval and recalled-memory rejection) persist `review_side_effect_started` before calling Hindsight. That state is never stale-auto-reopened or re-quarantined: after an ambiguous upstream/DB failure, retries fail closed instead of repeating a potentially successful retain/invalidate. Reconcile such a row manually before taking another action.
- `reviewed_allowed` and `reviewed_blocked` rows are decision state and are intentionally retained; admin cleanup does not purge them. A reviewed-allowed memory is reopened when stable content changes or when newly unsafe recalled extras require review.
- Oversized suspicious recalled content is not retained in full. The router records a bounded quarantine security-event placeholder containing source identity, stable digest, and scanner findings without the oversized payload.
- An `unknown_writer` retain that is unsafe cannot be directly approved after merely registering the writer. Resubmit it after registration so the normal retain scanner classifies it as `suspicious_content`, then review that quarantine item.

## CI dependency trust

- `scripts/generate_confusables_ascii.py` generates `memory_router/confusables_ascii.json` from Unicode UTS #39 17.0.0. Update the map, license, and `THIRD_PARTY_NOTICES.md` together.
- Pebble 5.2.1 runs facade scans in replaceable workers. Published images include its notice, LGPL-3.0/GPL-3.0 text, and source URL.
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
