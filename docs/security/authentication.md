# Authentication

[Documentation](../README.md) | [Repository](../../README.md)

Router and quarantine credentials are separate.

Set legacy router and admin tokens to at least 32 characters. Shorter tokens block startup.

## Principal mode

Set `MEMORY_ROUTER_PRINCIPALS=/path/principals.json`. This disables the shared router token. Startup rejects:

- `MEMORY_ROUTER_TOKEN`
- `MEMORY_ROUTER_ALLOW_ANONYMOUS=true`

Token: `mr_<key-id>_<64-lowercase-hex-secret>`.

Registry: SHA-256 secret digest only. Keys support `created_at`, `expires_at`, `revoked_at`. Key IDs are globally unique.

Scopes:

- `bank.list`
- `memory.recall`
- `memory.retain`
- `memory.reflect`
- `bank.config.read`
- `bank.config.write`
- `bank.admin`
- `quarantine.review`: read-only principal access to `GET /admin/quarantine/queue` and `GET /admin/quarantine/stats` metadata for granted banks; ciphertext fetch and review actions still require admin tokens
- `quarantine.decide`: reserved; no endpoints

Authorization is default-deny per principal, bank, and scope. `GET /v1/default/banks` keeps the upstream response shape and removes ungranted banks.

Facade reads of memory graphs, audit-log entries, LLM request traces, and operation payloads require `memory.recall`. Operation status without payloads and aggregate audit/LLM statistics keep `bank.config.read`. For operation detail, any true `include_payload` value requires `memory.recall`, including repeated query parameters; invalid boolean values return `400` in principal mode.

Optional `x-memory-router-agent`: must equal the token principal.

### Optional bank policy

In principal mode, `principal_registry.json` may restrict a bank:

```json
{"banks":{"personal":{"accessPolicy":{"allowedPrincipals":["personal-assistant"]}}}}
```

Omit `banks` to preserve existing behavior. Every bank operation requires both
an explicit principal grant and membership in `allowedPrincipals`. The policy
cannot create grants. Startup rejects grants to a restricted bank when the
principal is not listed. An empty list denies agent access. The dedicated
`control-plane` principal with `source: "control-plane"` keeps its explicit
grants for provisioning and is audited by the same authorization gate. Future
task access must use the parent's effective permissions via `inherited_banks`.

### Limits

| Class | Requests/min | Concurrency | Body |
| --- | ---: | ---: | ---: |
| recall | 120 | 4 | 32 KiB |
| retain | 30 | 2 | 512 KiB |
| reflect | 30 | 2 | 32 KiB |
| config/list | 60 | 2 | 128 KiB |
| admin | 10 | 1 | 128 KiB |

Override under registry `defaults.limits.<class>` or `principals.<id>.limits.<class>`:

- `rate_limit_max`
- `rate_limit_window_ms`
- `concurrency_max`
- `max_body_bytes`

Principal body limits cannot exceed `MEMORY_ROUTER_MAX_BODY_BYTES`.

Cluster mode stores principal rate counters and concurrency leases in PostgreSQL. PostgreSQL
availability is required for authenticated principal requests.

### Audit

`authorization_decision`: request ID, principal, key ID, bank, scope, decision, status, latency, source. No token, digest, or Authorization header. Successful authentications are not logged; failed attempts emit `authentication_failed`.

### Rotation

1. Add new key digest.
2. Restart router.
3. Update client token.
4. Set old `revoked_at`; restart.

## Legacy router token (deprecated)

`MEMORY_ROUTER_TOKEN` protects router endpoints when principal mode is off. Missing token fails closed unless `MEMORY_ROUTER_ALLOW_ANONYMOUS=true`. Anonymous mode is development-only: startup rejects it unless `MEMORY_ROUTER_HOST` is a loopback address.

Legacy token mode is deprecated and is removed at the next major release: startup logs a `legacy-router-token` configuration warning and authenticated responses carry a `Deprecation` header. Migrate to principal mode: create a principal registry (see `principal_registry.example.json`) with one principal per writer (unique key ID, SHA-256 secret digest, bank and scope grants), set `MEMORY_ROUTER_PRINCIPALS` to its path, unset `MEMORY_ROUTER_TOKEN`, and issue each caller a `mr_<key-id>_<secret>` token.

`/health/live` is anonymous and static. `/health/ready`, `/health`, and `/ready` answer anonymous callers with only `{"status": ...}`; the full upstream readiness payload requires router authentication. `/version` requires router authentication.

Legacy-mode memory operations are not logged on success; blocked or suspicious operations land in the quarantine review queue.

## Quarantine admin

- `MEMORY_ROUTER_ADMIN_READ_TOKEN`: read
- `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`: read and decide
- `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`: cleanup
- `MEMORY_ROUTER_ADMIN_TOKEN`: legacy all-scope superuser; deprecated and removed at the next major release (authenticated responses carry a `Deprecation` header)

Keep tokens out of Git, files, logs, prompts, and shell history.

## Optional human login: protocol contract

Human login is disabled by default and
requires principal mode. Existing application `mr_*` credentials remain supported;
human sessions do not replace application, administrative, or job credentials.

### Login and exchange

Use OpenID Connect authorization code flow with S256 PKCE through an external
browser ([OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html),
[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html),
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)). An operator configures one
HTTPS router origin, HTTPS issuer, and public native client ID. Discovery must return that exact issuer
and advertise S256. Issuer endpoints and signing keys come only from this trusted
configuration; callers cannot supply an issuer, client ID, or upstream URL.

1. The installer binds `127.0.0.1` on an ephemeral port and generates a state and
   PKCE verifier from 32 cryptographically random bytes each, encoded as 43-character
   unpadded base64url strings and kept in memory.
2. `POST /auth/human/start` accepts only `redirect_uri`, `state`, and
   `code_challenge`. The redirect must be `http://127.0.0.1:<port>/callback`, without
   user information, query, or fragment. The router stores a five-minute,
   single-use transaction binding these values, a fresh 32-byte random nonce, and the deployment
   policy generation. It returns `transaction_id` and `authorization_url`.
3. The installer opens the returned URL, accepts only the expected callback and
   matching state, and rejects duplicate response parameters. It sends
   `transaction_id`, `code`, `state`, and `code_verifier` to
   `POST /auth/human/exchange` over HTTPS.
4. The router verifies the bound challenge and state, atomically consumes the
   transaction, then redeems the code at the configured token endpoint with the
   original redirect and verifier. Failure requires a new login; retries cannot
   reuse the transaction. The database transaction ends before identity-provider
   I/O. Discovery, JWKS, and token requests use HTTPS without redirects, ten-second
   timeouts, and response caps of 64 KiB (discovery/token) or 256 KiB (JWKS).
5. A maintained JOSE library verifies the ID-token signature using trusted issuer
   keys and an explicit RS256 algorithm allowlist. Validation requires exact
   issuer, the configured client as the sole audience, nonempty subject, matching
   nonce, and valid `exp` and `iat`; future `iat`/`nbf` values are rejected. Token
   header URLs never select signing keys. OIDC tokens are discarded after use.

Only `openid` is requested. Arbitrary ID-token submission, implicit flow, password
flow, refresh tokens, and `offline_access` are unsupported. Browser callbacks and
exchange responses use `Cache-Control: no-store`. Router and identity-provider
bearer tokens never appear in URLs; the authorization code appears only in the
required loopback callback and is never logged. All installer requests carrying
credentials use the configured HTTPS router origin without redirects or protocol
downgrade. HTTP is permitted only for the loopback callback. The router exchange never accepts a Hindsight URL or returns
Hindsight credentials.

### Identity, grants, and session lifetime

An explicit server mapping of `(issuer, subject)` selects a stable human principal,
for example `human-example`. Email addresses, domains, request headers, and client
grant requests cannot select identity or elevate access. Human principals have no
persistent keys and use `source: "human"`; application principals still require
at least one key. Their allowed scopes are `bank.list`,
`memory.recall`, `memory.retain`, `memory.reflect`, and `bank.config.read`; existing
bank access policies and principal limits still apply. Administrative, control-plane,
quarantine, configuration-write, and delegation authority are excluded.

Successful exchange returns an opaque `mrh_<32-hex-key-id>_<64-hex-secret>`
credential, principal ID, authorized grants, and expiry. The key ID and secret use
16 and 32 random bytes respectively. The default and maximum lifetime is one hour. Only the secret's
SHA-256 digest is stored, with its expiry, revocation state, issued grant ceiling,
and policy generation. Every authenticated request checks shared session state;
effective grants are the intersection of issued and current `(bank, scope)` pairs,
further restricted by current bank access policy. Bank and scope lists must not be
intersected separately or recombined into new grants.
There is no positive authentication cache or fallback to another credential type.

`POST /auth/human/sign-out` revokes the caller's session. An operator must also be
able to revoke sessions through a server-side administrative command. Committed
revocation blocks subsequent authentication on every replica; operations already
admitted may finish. Expired or revoked credentials require explicit interactive
login again. Identity-provider logout is separate from router sign-out.

### Storage, deployment, and client requirements

Transactions, sessions, revocation, and login capacity use the existing database.
Rate/concurrency limits are local for one SQLite process and shared through
PostgreSQL for replicas. Transaction consumption is atomic across replicas. Strict request
schemas reject unknown fields and duplicate JSON keys, cap bodies at 8 KiB and
authorization codes at 4096 characters, and require exact 43-character base64url
state/challenge/verifier fields. Start and exchange admit at most 20 and 60 requests
per minute respectively across the deployment, including unsuccessful attempts.
At most eight identity-provider exchanges can run concurrently across replicas.
Limits are checked before provider I/O or state allocation; exhausted limits return
`429`. Expired state is pruned before allocation and by maintenance. Shared storage
caps are 1000 login transactions, 10,000 unexpired sessions, and 20 unexpired
sessions per human principal; revocation does not bypass these caps. Database failure
denies login and human authentication with `503`.

A shared active policy generation binds the HTTPS router origin, issuer/client configuration, identity
mapping, grants, and bank policy. Each replica checks it before starting or
consuming login transactions, issuing credentials, and authenticating sessions.
Issuance rechecks the generation after provider I/O. Mismatch fails closed. A replica cannot automatically replace an existing
generation. Operators explicitly activate configuration changes; activation
invalidates previous transactions and sessions, including on stale replicas.
Each explicit activation also increments a shared epoch. An exchange keeps the
epoch captured when its login transaction was consumed and must match it again
when issuing the session, even if the configuration digest is unchanged or restored.

The installer stores credentials only in supported OS secure storage. Its regular
configuration contains a credential reference bound to the HTTPS router origin
and server-returned principal ID, router URL, and routing metadata,
never the credential. Missing or locked secure storage stops installation before
configuration changes. Prompts, project files, CLI arguments, and logs must never
contain bearer tokens, authorization codes, verifiers, or identity claims.
Authentication failures must show that login is required, without silently using
an application token. Sign-out removes the local credential even if revocation
cannot be confirmed, and clearly reports that server-side limitation.

### Configuration and operations

Register a public native OIDC client supporting the loopback callback and S256,
then set `MEMORY_ROUTER_HUMAN_AUTH` to a JSON file:

```json
{"router_url":"https://router.example","issuer":"https://identity.example","client_id":"coding-agents","subjects":{"synthetic-subject":"human-example"}}
```

Add a human entry to the principal registry:

```json
{"principals":{"human-example":{"source":"human","keys":[],"grants":[{"bank":"personal","scopes":["bank.list","memory.recall","memory.retain"]}]}}}
```

Use the same configuration files and database for all replicas. Initial startup
activates the first policy generation. After configuration changes, run
`memory-router-human-auth activate` with the updated environment and restart
replicas with those files. Activation immediately invalidates all human sessions
and pending logins, even when reactivating an earlier or unchanged configuration.
Stale replicas fail closed until updated.

Revoke a session using `memory-router-human-auth revoke --key-id <key-id>`.
The key ID is nonsecret; never pass a bearer token to this command. Application
principal rotation remains unchanged.
