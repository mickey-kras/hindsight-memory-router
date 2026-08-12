# Runtime interaction map

This document describes the current runtime behavior of Memory Router. It is intended to be the as-built reference for request routing, security decisions, quarantine, review state, maintenance, and Hindsight interaction.

## Request entry

```mermaid
flowchart TD
    Client[OpenClaw Hindsight plugin] --> HTTP[Uvicorn :8890]
    HTTP --> RID[RequestIdMiddleware]
    RID --> App[FastAPI]

    App --> Live[GET /health/live]
    App --> Health[GET /health or /health/ready]
    App --> LegacyReady[GET /ready deprecated alias]
    App --> Admin{Path starts /admin/?}

    Live --> L200[200 router liveness; no dependency I/O]

    Health --> Checks[Run readiness checks in parallel]
    LegacyReady --> Checks
    Checks --> RouterDB[Quarantine DB ping]
    Checks --> HHealth[Hindsight GET /health]
    HHealth --> HDB[Hindsight checks its DB]
    RouterDB --> Ready{Both healthy?}
    HDB --> Ready
    Ready -->|yes| H200[200 validated Hindsight health JSON unchanged]
    Ready -->|no| H503[503 status: unhealthy]

    Admin -->|yes| AdminAuth[Scoped admin auth]
    Admin -->|no| RouterAuth[Router bearer auth]

    AdminAuth -->|authorized| AdminRate[Admin read/write rate limit]
    AdminAuth -->|recognized token, wrong scope| A401[401]
    AdminAuth -->|unknown/invalid token| AuthFailA[Auth-failure limit + audit]
    AuthFailA --> A401

    RouterAuth -->|authorized| RouterDispatch[Router dispatch]
    RouterAuth -->|failure| AuthFailR[Auth-failure limit + audit]
    AuthFailR --> R401[401]

    RouterDispatch --> Version[GET /version]
    RouterDispatch --> Retain[Retain]
    RouterDispatch --> Recall[Recall]
    RouterDispatch --> Denied[Denied endpoint security event + 404]

    AdminRate --> AdminDispatch[Admin quarantine API]
```

Health endpoints are unauthenticated. `/health/live` is router-process liveness only. `/health` and `/health/ready` are exact readiness aliases: they require both router quarantine storage and Hindsight `/health` to succeed. The legacy `/ready` endpoint is deprecated and uses the same readiness behavior. A successful readiness response is the validated Hindsight `/health` JSON returned unchanged; dependency failure returns `503 {"status":"unhealthy"}`.

`RequestIdMiddleware` accepts a valid incoming `X-Request-ID` or generates one. The request ID is returned to the client and forwarded to Hindsight.

## Startup and shutdown

```mermaid
flowchart TD
    Start[Process start] --> NoPrivate[Reject QUARANTINE_PRIVATE_KEY* environment]
    NoPrivate --> AuthConfig[Validate auth/deployment settings]
    AuthConfig --> DB[Open SQLite or PostgreSQL]
    DB --> Validate[Validate storage]
    Validate --> Recover[Recover stale review_in_progress items]
    Recover --> Pg{PostgreSQL?}

    Pg -->|yes| PgLimits[Initialize shared PostgreSQL rate limits]
    Pg -->|no| MemoryLimits[Initialize process-local rate limits]

    PgLimits --> Key[Decode quarantine public key]
    MemoryLimits --> Key
    Key --> Store[Create QuarantineStore]
    Store --> Hindsight[Create HindsightGateway]
    Hindsight --> Limits[Create Hindsight limits]
    Limits --> Registry[Load writer registry]
    Registry --> Policy[Create RouterPolicy]
    Policy --> Admin[Create admin service]
    Admin --> Auditor[Create auth-failure auditor]
    Auditor --> Sweeper{Sweep interval > 0?}
    Sweeper -->|yes| Task[Start maintenance task]
    Sweeper -->|no| Serve[Serve traffic]
    Task --> Serve

    Stop[Shutdown] --> Cancel[Cancel maintenance task]
    Cancel --> CloseH[Close Hindsight client]
    CloseH --> CloseRL[Close PostgreSQL rate-limit pool]
    CloseRL --> CloseDB[Close repository]
```

Cluster mode requires PostgreSQL quarantine storage and an external shared admin rate limiter. SQLite and in-memory rate limits are single-process only.

## Retain

```mermaid
flowchart TD
    Req[POST /v1/default/banks/{writer}/memories] --> Body[Bound request body]
    Body --> JSON[Strict JSON + max nesting depth]
    JSON --> Validate[Validate RetainBody]
    Validate --> Bounds[Retain item/string byte bounds]
    Bounds --> Writer{Writer registered?}

    Writer -->|no| Unknown[Quarantine retain_request: unknown_writer]
    Unknown --> Queued[Return queued + quarantine_id]

    Writer -->|yes| Scan[Scan all string keys and values]
    Scan --> Safe{Safe?}
    Safe -->|no| Suspicious[Quarantine retain_request: suspicious_content]
    Suspicious --> Queued

    Safe -->|yes| Rewrite[Inject router provenance metadata]
    Rewrite --> Rate[Consume writer + global retain quota]
    Rate --> Hindsight[POST assigned Hindsight write bank]
    Hindsight --> Response[Return Hindsight response]
```

The security scan includes canonicalization, deterministic router rules, Agent Memory Guard detectors, rolling cross-field scans, and direct/split Base64 inspection.

Unknown or suspicious requests do not consume normal Hindsight retain quota.

## Recall

```mermaid
flowchart TD
    Req[POST .../{writer}/memories/recall] --> Parse[Bound body + strict JSON + schema]
    Parse --> Bounds[Query/max_tokens bounds]
    Bounds --> Writer{Writer registered?}

    Writer -->|no| QU[Attempt quarantine: unknown_writer]
    QU --> EmptyU[Return results: []]

    Writer -->|yes| Scan[Scan all recall request strings/keys]
    Scan --> SafeQ{Safe?}
    SafeQ -->|no| QS[Attempt quarantine: suspicious_query]
    QS --> EmptyS[Return results: []]

    SafeQ -->|yes| Limit[Consume writer + global recall quota]
    Limit --> Fanout[Recall all allowed read banks in parallel]

    Fanout --> Validate[Per-bank HTTP/size/JSON/depth/shape validation]
    Validate -->|typed Hindsight failure| Drop[Log degradation and drop bank]
    Validate -->|valid| Results[Process recalled results]

    Results --> State[Lookup quarantine state by bank + memory id]
    State --> Blocked{Blocked or review state?}
    Blocked -->|yes| Suppress[Suppress result]

    Blocked -->|no| Approved{reviewed_allowed and id+text digest unchanged?}
    Approved -->|yes| Volatile[Scan volatile fields only]
    Volatile -->|safe| Return[Return result]
    Volatile -->|unsafe| Quarantine[Quarantine/reopen and suppress]

    Approved -->|no| Full[Scan full recalled result]
    Full -->|safe| Return
    Full -->|unsafe| Quarantine

    Quarantine --> QResult{Quarantine available?}
    QResult -->|yes| Suppress
    QResult -->|capacity/rate/review conflict| Degrade[Log degradation]
    Degrade --> Suppress
```

A typed Hindsight failure affects only the failing read bank. If all banks fail, recall returns an empty result set. Suspicious recalled material is suppressed even when quarantine cannot accept it.

## Quarantine admission

```mermaid
flowchart TD
    Candidate[Quarantine candidate] --> ID[Resolve quarantine identity]
    ID --> Size[Preflight encrypted-envelope size]
    Size -->|too large| E413[413 quarantine_item_too_large]

    Size --> Existing[Check existing identity]
    Existing --> Known{Known/repeated identity?}
    Known -->|yes| ReQ[Requarantine operation quota]
    Known -->|no| Admission[Writer/global/distinct-family admission]

    ReQ --> Lock[Identity lock]
    Admission --> Lock
    Lock --> ReRead[Re-read item under lock]
    ReRead --> Review{Item under review?}
    Review -->|yes| E409[409 review conflict]

    Review -->|no| Encrypt[AES-256-GCM payload encryption]
    Encrypt --> Wrap[RSA-OAEP-SHA256 key wrap]
    Wrap --> Capacity[Atomic pending/per-writer/byte capacity]
    Capacity -->|exhausted| E507[507 capacity exceeded]
    Capacity --> Store[Store current item]
    Store --> Event[Append audit event]
```

`quarantine_items` stores current quarantine/review state. `quarantine_events` stores audit history.

## Review lifecycle

```mermaid
stateDiagram-v2
    [*] --> pending: quarantined
    pending --> postponed: postpone
    postponed --> postponed: postpone
    pending --> expired: TTL
    postponed --> expired: TTL

    pending --> review_in_progress: approve recalled memory
    postponed --> review_in_progress: approve recalled memory
    review_in_progress --> reviewed_allowed: approval finalized
    review_in_progress --> postponed: stale recovery

    pending --> review_side_effect_started: approve retained request
    postponed --> review_side_effect_started: approve retained request
    pending --> review_side_effect_started: reject recalled memory
    postponed --> review_side_effect_started: reject recalled memory

    review_side_effect_started --> pending: definite failure from pending
    review_side_effect_started --> postponed: definite failure from postponed
    review_side_effect_started --> review_side_effect_completed: Hindsight side effect confirmed

    review_side_effect_completed --> [*]: approved retain finalized
    review_side_effect_completed --> reviewed_blocked: recalled memory rejection finalized

    pending --> [*]: reject non-memory item
    postponed --> [*]: reject non-memory item

    reviewed_allowed --> pending: content changed / safety reopened
```

### Retain approval

```text
offline decrypt
-> exact canonical SHA + metadata verification
-> writer must exist
-> parse original retain again
-> security scan again
-> bounds again
-> Hindsight retain quota
-> claim review_side_effect_started
-> Hindsight retain
-> checkpoint review_side_effect_completed
-> delete quarantine item + append approved event
```

### Recalled-memory approval

```text
exact decrypted object verification
-> claim review_in_progress
-> mark reviewed_allowed
-> remove encrypted payload
-> allow future recall only while stable id+text digest matches
```

### Recalled-memory rejection

```text
claim review_side_effect_started
-> invalidate memory in Hindsight
-> checkpoint review_side_effect_completed
-> mark reviewed_blocked
-> remove encrypted payload
```

## Maintenance

```mermaid
flowchart LR
    Timer[Maintenance interval] --> Recover[Recover stale review_in_progress]
    Recover --> Expire[Sweep expired pending/postponed items]
    Expire --> Events[Prune old audit events]
```

Pending/postponed TTL and event retention are independently configurable. Side-effect checkpoint states are not treated as normal stale review claims.

## Rate-limit topology

```mermaid
flowchart TD
    Request[Request] --> Auth[Auth failures]
    Request --> Admin[Admin API]
    Request --> Quarantine[Quarantine writes]
    Request --> Retain[Hindsight retain]
    Request --> Recall[Hindsight recall]

    Auth --> Shared[SQLite: in-memory / PostgreSQL: shared DB limiter]
    Quarantine --> Shared
    Retain --> Shared
    Recall --> Shared

    Admin --> Local[Process-local admin limiter]
    Cluster[Cluster mode] --> External[External shared admin limiter required]
```

PostgreSQL rate limiting uses database time and transaction-scoped advisory locks.

## Build and pull-request validation

```mermaid
flowchart TD
    PR[Pull request] --> CI[ci workflow]
    CI --> Lock[Python lock verification]
    Lock --> Hygiene[No legacy TypeScript runtime/tests]
    Hygiene --> Ruff[Ruff]
    Ruff --> Mypy[mypy strict]
    Mypy --> OpenAPI[OpenAPI contract]
    OpenAPI --> Tests[pytest + coverage >= 90%]
    Tests --> Audit[pip-audit + npm audit + Bandit]
    Audit --> Security[Gitleaks + Semgrep]
    Security --> Docker[Hadolint + Docker build]
    Docker --> Compose[Default + fake Hindsight + real Hindsight smoke]

    PR --> Aislop[Aislop quality gate + SARIF]
    PR --> Container[Publish workflow container job]
    Container --> Image[Build local image]
    Image --> Trivy[Trivy PR image gate]
```

## Publish workflow

```mermaid
flowchart TD
    Main[Push main or version tag] --> ScanJob[container job]
    ScanJob --> BuildScan[Build local image]
    BuildScan --> Trivy[Trivy report + HIGH/CRITICAL gate]
    Trivy --> Publish[publish job]

    Publish --> GHBuild[Build + push GHCR image]
    Publish --> DHBuild[Build + push Docker Hub image]
    GHBuild --> GHSign[Cosign sign + provenance attestation]
    DHBuild --> DHSign[Cosign sign + provenance attestation]
```

The production-readiness implications of this current workflow are tracked separately in [Production readiness](../operations/production-readiness.md).
