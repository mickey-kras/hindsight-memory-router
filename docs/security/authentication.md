# Authentication

[Documentation](../README.md) | [Repository](../../README.md)

Router and quarantine credentials are separate.

Set the legacy router and admin tokens to a minimum of 32 characters. Shorter tokens block startup.

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
- `quarantine.review`: read-only principal access to `GET /admin/quarantine/queue` and `GET /admin/quarantine/stats` metadata for granted banks. Ciphertext fetch and review actions must have admin tokens
- `quarantine.decide`: reserved. No endpoints use it

Authorization is default-deny per principal, bank, and scope. `GET /v1/default/banks` keeps the upstream response shape and removes ungranted banks.

Facade reads of memory graphs, audit-log entries, LLM request traces, and operation payloads must have `memory.recall`.
Operation status without payloads and aggregate audit and LLM statistics must have `bank.config.read`.
For operation detail, each true `include_payload` value must have `memory.recall`. This includes repeated query parameters.
Invalid boolean values return `400` in principal mode.

Optional `x-memory-router-agent`: must equal the token principal.

### Optional bank policy

In principal mode, `principal_registry.json` can restrict a bank:

```json
{"banks":{"personal":{"accessPolicy":{"allowedPrincipals":["personal-assistant"]}}}}
```

Omit `banks` to preserve existing behavior.
Every bank operation must have an explicit principal grant and membership in `allowedPrincipals`.
Grants come only from the registry, not from the policy. If a restricted bank does not list the principal, startup rejects grants to that bank.
An empty list denies agent access.

The dedicated `control-plane` principal with `source: "control-plane"` keeps its explicit provisioning grants.
The same authorization gate audits this principal.
Future task access must use the parent's effective permissions through `inherited_banks`.

### Limits

| Class | Requests per minute | Concurrency | Body |
| --- | ---: | ---: | ---: |
| recall | 120 | 4 | 32 KiB |
| retain | 30 | 2 | 512 KiB |
| reflect | 30 | 2 | 32 KiB |
| config and list | 60 | 2 | 128 KiB |
| admin | 10 | 1 | 128 KiB |

Override under registry `defaults.limits.<class>` or `principals.<id>.limits.<class>`:

- `rate_limit_max`
- `rate_limit_window_ms`
- `concurrency_max`
- `max_body_bytes`

Principal body limits cannot be more than `MEMORY_ROUTER_MAX_BODY_BYTES`.

Cluster mode stores principal rate counters and concurrency leases in PostgreSQL. PostgreSQL
availability is necessary for authenticated principal requests.

### Audit

`authorization_decision` contains request ID, principal, key ID, bank, scope, decision, status, latency, and source.
It excludes tokens, digests, and the Authorization header.
The router does not log successful authentications. Failed attempts emit `authentication_failed`.

### Rotation

1. Add the new key digest.
2. Restart the router.
3. Update the client token.
4. Set the old key's `revoked_at`.
5. Restart the router.

## Legacy router token (deprecated)

`MEMORY_ROUTER_TOKEN` protects router endpoints when principal mode is off. Missing token fails closed unless `MEMORY_ROUTER_ALLOW_ANONYMOUS=true`. Anonymous mode is development-only: startup rejects it unless `MEMORY_ROUTER_HOST` is a loopback address.

Do not use legacy token mode. It is a deprecated mode, and the next major release removes it.
Startup logs a `legacy-router-token` configuration warning. Authenticated responses carry a `Deprecation` header.

To migrate to principal mode:

1. Create a principal registry with one principal per writer. See `principal_registry.example.json`.
2. Give each principal a unique key ID, SHA-256 secret digest, and bank and scope grants.
3. Set `MEMORY_ROUTER_PRINCIPALS` to the registry path.
4. Unset `MEMORY_ROUTER_TOKEN`.
5. Issue each caller a `mr_<key-id>_<secret>` token.

`/health/live` is anonymous and static. `/health/ready`, `/health`, and `/ready` answer anonymous callers with only `{"status": ...}`. The full upstream readiness payload is available only with router authentication. `/version` is available only with router authentication.

The router does not log successful legacy-mode memory operations.
Blocked or suspicious operations enter the quarantine review queue.

## Quarantine admin

- `MEMORY_ROUTER_ADMIN_READ_TOKEN`: read
- `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`: read and decide
- `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`: cleanup
- `MEMORY_ROUTER_ADMIN_TOKEN`: deprecated legacy superuser for all scopes. The next major release removes it. Authenticated responses carry a `Deprecation` header

Keep tokens out of Git, files, logs, prompts, and shell history.

## Optional human login: protocol contract

Human login is off by default.
It is only for principal mode. The router still accepts existing application `mr_*` credentials.
Human sessions do not replace application, administrative, or job credentials.

### Login and exchange

Use the authorization code flow of OpenID Connect, with S256 PKCE, through an external browser.
See [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html), and [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).
Configure one HTTPS router origin, HTTPS issuer, and public native client ID.
Discovery must return that exact issuer and advertise S256.
Issuer endpoints and signing keys come only from this trusted configuration.
Callers cannot supply an issuer, client ID, or upstream URL.

OIDC discovery, token, and signing-key requests send `Accept-Encoding: identity`.
Responses must omit `Content-Encoding` or use `identity`.
The router rejects other encodings before body decoding to preserve response-size limits.

1. The installer binds `127.0.0.1` on an ephemeral port.
   It generates a state and PKCE verifier from 32 cryptographically random bytes each.
   It encodes each value as a 43-character unpadded base64url string and keeps both values in memory.
2. `POST /auth/human/start` accepts only `redirect_uri`, `state`, and `code_challenge`.
   The redirect must be `http://127.0.0.1:<port>/callback`, without user information, query, or fragment.
   The router stores a five-minute, single-use transaction.
   The transaction binds these values, a fresh 32-byte random nonce, and the deployment policy generation.
   The endpoint returns `transaction_id` and `authorization_url`.
3. The installer opens the returned URL.
   It accepts only the expected callback and matching state.
   It rejects duplicate response parameters.
   It sends `transaction_id`, `code`, `state`, and `code_verifier` to `POST /auth/human/exchange` over HTTPS.
4. The router examines the bound challenge and state.
   It atomically consumes the transaction.
   It redeems the code at the configured token endpoint with the original redirect and verifier.
   After a failure, a new login is necessary.
   Retries cannot reuse the transaction.

   The database transaction ends before identity-provider I/O.

   Discovery, JWKS, and token requests use HTTPS without redirects and ten-second timeouts.
   Response caps are 64 KiB for discovery and token responses, and 256 KiB for JWKS.
5. A maintained JOSE library examines the ID-token signature with trusted issuer keys and an explicit RS256 algorithm allowlist.
   Validation must have the exact issuer, the configured client as sole audience, a nonempty subject, and a matching nonce.
   It must also have valid `exp` and `iat`.
   Validation rejects future `iat`/`nbf` values.
   Token header URLs never select signing keys.

   After use, the router discards the OIDC tokens.

The router requests only `openid`.
It does not support arbitrary ID-token submission, implicit flow, password flow, refresh tokens, or `offline_access`.
Browser callbacks and exchange responses use `Cache-Control: no-store`.
Router and identity-provider bearer tokens never appear in URLs.
The authorization code appears only in the mandatory loopback callback. Logs never contain this code.

All installer requests carrying credentials use the configured HTTPS router origin without redirects or protocol downgrade.
Use HTTP only for the loopback callback.
The router exchange never accepts a Hindsight URL or returns Hindsight credentials.

### Identity, grants, and session lifetime

An explicit server mapping of `(issuer, subject)` selects a stable human principal, for example `human-example`.
Email addresses, domains, request headers, and client grant requests cannot select identity or increase access.
Human principals have no persistent keys and use `source: "human"`.
Application principals must have a minimum of one key.

Allowed human scopes are `bank.list`, `memory.recall`, `memory.retain`, `memory.reflect`, and `bank.config.read`.
Existing bank access policies and principal limits still apply.
Human principals have no administrative, control-plane, quarantine, configuration-write, or delegation authority.

Successful exchange returns an opaque `mrh_<32-hex-key-id>_<64-hex-secret>` credential, principal ID, authorized grants, and expiry.
The key ID and secret use 16 and 32 random bytes respectively.
The default and maximum lifetime is one hour.
Storage contains only the secret's SHA-256 digest, expiry, revocation state, issued grant ceiling, and policy generation.
Every authenticated request checks shared session state.

Effective grants are the intersection of issued and current `(bank, scope)` pairs, further restricted by current bank access policy.
Do not intersect bank and scope lists separately.
Do not recombine these lists into new grants.
There is no positive authentication cache or fallback to another credential type.

`POST /auth/human/sign-out` revokes the caller's session. An operator must also be
able to revoke sessions through a server-side administrative command. After a revocation commits, it blocks all later authentication on every replica.
Operations that the router admitted before can finish. Expired or revoked credentials must have an explicit interactive
login again. Identity-provider logout is separate from router sign-out.

### Storage, deployment, and client requirements

Transactions, sessions, revocation, and login capacity use the existing database.
Rate and concurrency limits are local for one SQLite process. Replicas share them through PostgreSQL.
Transaction consumption is atomic across replicas.

Strict request schemas reject unknown fields and duplicate JSON keys.
They cap bodies at 8 KiB and authorization codes at 4096 characters.
They must have exact 43-character base64url fields for state, challenge and verifier.

Start and exchange admit at most 20 and 60 requests per minute respectively across the deployment.
These limits include unsuccessful attempts.
At most eight identity-provider exchanges can run concurrently across replicas.
Limit checks occur before provider I/O or state allocation.
Exhausted limits return `429`.
The router prunes expired state before allocation and during maintenance.

Shared storage caps are 1000 login transactions, 10,000 unexpired sessions, and 20 unexpired sessions per human principal.
Revocation does not bypass these caps.
Database failure denies login and human authentication with `503`.

A shared active policy generation binds the HTTPS router origin, the issuer and client configuration, identity mapping, grants, and bank policy.
Each replica checks the generation before it starts or consumes login transactions, issues credentials, or authenticates sessions.
Issuance rechecks the generation after provider I/O.
A mismatch fails closed.
A replica cannot automatically replace an existing generation.

Operators explicitly activate configuration changes.
Activation invalidates previous transactions and sessions, including on stale replicas.
Each explicit activation also increases a shared epoch.
An exchange keeps the epoch captured during consumption of its login transaction.
The epoch must match again during session issuance, even if the configuration digest did not change or has its old value again.

The installer stores credentials only in supported OS secure storage.
Regular configuration contains a credential reference bound to the HTTPS router origin and server-returned principal ID.
It also contains the router URL and routing metadata, but never the credential.
Missing or locked secure storage stops installation before configuration changes.
Prompts, project files, CLI arguments, and logs must never contain bearer tokens, authorization codes, verifiers, or identity claims.

Authentication failures must show that a login is necessary.
They must not silently use an application token.
Sign-out removes the local credential even if the client cannot confirm revocation.
It clearly reports this server-side limitation.

### Configuration and operations

Register a public native OIDC client that supports the loopback callback and S256.
Set `MEMORY_ROUTER_HUMAN_AUTH` to a JSON file:

```json
{"router_url":"https://router.example","issuer":"https://identity.example","client_id":"coding-agents","subjects":{"synthetic-subject":"human-example"}}
```

Add a human entry to the principal registry:

```json
{"principals":{"human-example":{"source":"human","keys":[],"grants":[{"bank":"personal","scopes":["bank.list","memory.recall","memory.retain"]}]}}}
```

Use the same configuration files and database for all replicas.
Initial startup activates the first policy generation.
After configuration changes, run `memory-router-human-auth activate` with the updated environment.
Restart replicas with the updated files.
Activation immediately invalidates all human sessions and pending logins, even for an earlier or unchanged configuration.
Stale replicas fail closed until updated.

Revoke a session using `memory-router-human-auth revoke --key-id <key-id>`.
The key ID is not secret.
Never pass a bearer token to this command. Application
principal rotation does not change.

