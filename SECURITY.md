# Security Policy

[Documentation](docs/README.md) | [Repository](README.md)

## Reporting

Use a private GitHub security advisory.

## Boundaries

- Router token: authenticates a trusted client for retain and recall. It does not authenticate an individual writer identity.
- The authenticated client selects `writer_id` for routing and policy. It is not a per-writer credential. Do not give one shared router token to mutually untrusted agents if writer-bank isolation is a security requirement.
- Registry bank names and the read and write topology of writers are deployment policy. The router has no built-in `main`-cannot-read-`research` invariant.
  If a deployment must have this isolation, write it in the registry and governance of that deployment.
  Validate the resulting policy. Do not rely on a bank-name special case.
- Read token: queue, stats, encrypted items.
- Review token: read plus approve, reject, postpone.
- Cleanup token: cleanup only.
- Legacy admin token: migration only. After the migration, do not set it.
- Authentication fails closed. Token comparisons are timing-safe. The router never logs tokens.
- A recognized admin token outside its allowed scope returns the same generic 401 as other authorization failures.
  It does not consume the bad-token throttle budget or enter the auth-failure audit. This prevents a valid mis-scoped client from exhausting the shared authentication-failure budget.
- The private quarantine key must never enter the router runtime.
- Approval must have the exact decrypted object and stored hash. Before a review claim commits a decision, it pins the `sha256` and `updated_at` snapshot of the row under the database row lock.
- Hindsight failures expose only stable router error codes and generic messages. The router discards upstream error bodies without inspection. Diagnostics contain only fixed bounded metadata.

## Content scanning

The scanner detects selected threats. It is not a security boundary. It scans string keys and values in retain, recall, facade, query, and Hindsight responses.
It normalizes Unicode, checks bounded standard Base64, and applies explicit rules. Keep ACLs, request limits, quarantine, exact-hash review, and human review.

### Fail-closed limits

| Scope | Limit |
| --- | --- |
| Retain, recall, facade request | 5-second cooperative deadline |
| Query | 256 pairs, 10-second deadline, 32,768 rolling windows total and skip windows per group |
| Facade response | 256 KiB, 8,192 fields, 30-second deadline |
| Other rolling or skip scans | 8,192 windows per value, key, or traversal group |
| String | 1 MiB, 65,536 non-ASCII code points |
| Confusable variants | 32 per field or window |
| Split Base64 | 64 candidates, 256 fragments, 512 KiB candidate work, two skipped fragments |

The scanner checks deadlines between scan units. Deadlines do not interrupt a scan unit. Authenticated requests consume quota before scanning. Unknown writers and cheap structural failures do not.

### Base64

Split reconstruction covers whitespace-, punctuation-, and label-separated chunks, serialized JSON values, dictionary keys, and adjacent key and value fragments. It can skip two fragments within a five-field span. Limit exhaustion returns `split_base64_limit`. This can quarantine benign Base64-like content.

Hard Base64 evidence (`=`, `+`, or `/`) fails closed on invalid encoding or UTF-8. Mixed-case tokens with digits are weak hints. For this reason, the scanner ignores valid binary identifiers.
The scanner decodes padded and unpadded standard Base64 through one nested layer. It does not decode Base64url.

### Unicode and instruction rules

Scanning uses NFKC, semantic folds, Latin-diacritic removal, and vendored Unicode UTS #39 17.0.0 ASCII skeletons. The scanner preserves non-ASCII skeletons. Invisible and control Unicode characters fail closed.
The scanner preserves script marks for Indic, Arabic, and Hebrew text.

Phrase and word boundaries reduce false positives. Related inflections can fail to match. Split scans exclude `system prompt`, `developer message`, and `new instructions` unless another detector or a complete field matches. The scanner suppresses separate bare `api`/`key` and `private`/`key` fields when only version tokens occur between them.

Reviewed recall approvals bind stable memory identity and content (`id` + `text`). When the digest matches, approved `id`/`text` stays reconstruction context during each recall scan.
A finding gets an exemption only if it is fully in one exact approved field occurrence.
Volatile fields and instructions spanning approved and volatile fields still suppress the result and reopen review.
This includes repeated matches of an approved rule.

The approval digest does not bind object field order. Findings assembled across `id` and `text` also suppress the result, including within one approved memory.
Scanner limits and unknown provenance fail closed. The router also scans the assembled response across results, banks, and supplemental entries.
It treats numeric scalars as unreviewed content. Finite integer-valued floats keep their original spelling and also scan as the same decimal integers within existing budgets.

Separate approvals cannot jointly approve a newly reconstructed finding. The router suppresses unsafe aggregates in full.
Audit attempts include only a content digest and stable reason and detector identifiers. They never include matched provider text.
Suppression continues if audit storage fails.

Single-bank recalls scope aggregate audit identity and pending capacity to the requested bank. Multi-bank aggregate audits stay unscoped.
Aggregate scanning keeps the existing field, window and time budgets. For this reason, larger safe combinations can fail closed.
Compact joins can extend an approved token with otherwise benign untrusted numeric metadata. The router suppresses these ambiguous combinations.

The Hindsight adapter certifies only validated backend-generated `results[].scores` (`final`, `reranker`, `semantic`, `keyword`).
The aggregate scan copy excludes their digits but preserves field accounting. API responses keep the original scores.
The scanner does a normal scan of unknown or malformed score objects, nested metadata and changed values.
Only the adapter supplies certification. JSON keys and reviewed-content approvals cannot supply it.

## Quarantine lifecycle

- The periodic sweep recovers stale `review_in_progress` claims. Approve, reject, and postpone actions also recover them on demand. Disabling the periodic sweep does not make stale review claims permanent.
- On-demand recovery deletes or expires an expired stale review claim in a transaction.
  It does not restore a permanently blocked `review_in_progress` row.
- Non-idempotent admin operations (`retain` approval and recalled-memory rejection) store `review_side_effect_started` before they call Hindsight. The router never automatically reopens or requarantines that state after a stale claim.
  After an ambiguous upstream or database failure, retries fail closed. They do not repeat a retain or invalidate that possibly succeeded. Reconcile such a row manually before taking another action.
- `reviewed_allowed` and `reviewed_blocked` rows store decisions. Admin cleanup retains them.
  The router reopens a reviewed-allowed memory when stable content changes or when new unsafe recalled extras must have a review.
- The router does not keep oversized suspicious recalled content in full. The router records a bounded quarantine security-event placeholder containing source identity, stable digest, and scanner findings without the oversized payload.
- If an `unknown_writer` retain is unsafe, registration of the writer alone does not let you approve it. Resubmit it after registration. The normal retain scanner classifies it as `suspicious_content`.
  Review that quarantine item.

## CI dependency trust

- `build-requirements.txt` hash-locks the Python build backend separately from runtime and development dependencies. Regenerate it with `make build-requirements` when changing `build-system.requires`. Regeneration can download and execute newly declared backends before their new hashes exist.
  Run regeneration only for trusted backend changes.

  Review the resulting lock. CI validates the reviewed backend lock without build isolation. Container builds install only backend wheels with a correct hash. They build the project without networking or build isolation.
  Build tools stay in the builder stage.
- `scripts/generate_confusables_ascii.py` generates `memory_router/confusables_ascii.json` from Unicode UTS #39 17.0.0. Update the map, license, and `THIRD_PARTY_NOTICES.md` together.
- Pebble 5.2.1 runs facade scans in replaceable workers. Published images include its notice, LGPL-3.0/GPL-3.0 text, and source URL.
- Aislop is an exact npm dev dependency and runs through local npm scripts. Dependabot updates it.
- Semgrep uses a versioned image pinned by digest. Update the version and digest together.
- GitHub Actions stay pinned by commit SHA.
- The allowlist permits Dependabot auto-merge only for semantic-version patch and minor updates. Major, unclassified and non-semver updates must have a human review.

## Deployment

- `single`: one router process with SQLite or PostgreSQL.
- `cluster`: PostgreSQL plus a real shared admin limiter.
- The built-in admin request limiter is local to each process with SQLite.
  PostgreSQL shares admin limiter state across replicas.
  Cluster deployments must also enforce the shared admin limit externally.
  `MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true` only asserts that this external limiter exists.

See `docs/DEPLOYMENT_MODES.md`.

## Token migration

1. Add scoped tokens.
2. Restart the router.
3. Migrate clients.
4. Examine the clients.
5. Remove the legacy token.
6. Restart the router.

## Runtime

- Private network.
- Do not expose Hindsight directly.
- Run as non-root.
- Keep quarantine storage separate.

## Compatibility

The Python runtime authorizes admin requests with scoped tokens configured through `MEMORY_ROUTER_ADMIN_READ_TOKEN`, `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`, and `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`. `MEMORY_ROUTER_ADMIN_TOKEN` is a temporary environment variable for the legacy superuser. Use it only for migration.

## Non-goal

The router does not secure Hindsight itself.

## Dependency licenses

Dependency review blocks high and critical vulnerabilities in runtime, development,
and unknown scopes. Reviewers check license compatibility manually. CI does not certify it.

- A separately executed CI tool (for example, the SonarSource scanner) does not get a
  license exception for each version. Review actual changes to their license or usage.
- Before you add or change shipped dependencies, review their applicable terms, linking and bundling, notices, and source and relinking duties.
  This applies to binaries, packages, and containers.
- GPL, AGPL, LGPL, SSPL, custom, and unknown terms must have a review of their context. They do not cause an automatic ban.
  Record the decision and the necessary notices in the PR.
  Update the third-party notices when they change.
- Existing dependencies are not proof of approval. Review any unrecorded shipped
  dependency before relying on its licensing. Disable auto-merge when a manual review is necessary.

The repository's own license does not replace dependency licenses.

