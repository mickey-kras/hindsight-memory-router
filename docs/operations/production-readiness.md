# Production readiness

See [Application logs](logging.md) for the JSON event schema, readiness transitions, and the fields that must never be logged.

This document tracks production-readiness findings against the current runtime interaction map. It is intentionally separate from the architecture reference so current behavior and recommended changes remain distinct.

See [Runtime interaction map](../architecture/runtime-interactions.md) for the as-built workflows.

## Current status

| Area | Status | Note |
| --- | --- | --- |
| Request parsing and bounds | Ready | Strict JSON, size/depth bounds, schema validation |
| Authentication | Ready | Router and scoped admin auth fail closed |
| Retain security boundary | Ready | Full string/key scanning before provider call |
| Recall security boundary | Ready | Request/result scanning and suppression on quarantine degradation |
| Quarantine encryption | Ready | Public-key-only router, AES-256-GCM payload encryption |
| Quarantine capacity/dedupe/rate limits | Ready | Atomic storage limits and request-family controls |
| Multi-bank recall degradation | Ready | Typed per-bank failure isolation |
| Provider response validation | Ready | Size, JSON, depth, finite-number and response-shape checks |
| Health/readiness contract | Ready | `/health/live` is router liveness; `/health` and `/health/ready` require router storage + Hindsight health |
| Review concurrency | Ready | Snapshot checks and review claims |
| Non-idempotent review side-effect protection | Ready | Explicit side-effect checkpoint states prevent blind replay |
| Ambiguous review side-effect reconciliation | Blocked | No supported transition out of `review_side_effect_started` after an ambiguous provider outcome |
| Router provenance source | Needs correction | Runtime defaults policy source to `openclaw` instead of using the agent-neutral registry source |
| Build/publish artifact identity | Blocked | Trivy scans one build; publish jobs rebuild independently before pushing/signing |
| SonarQube Community gate | Pending | Planned static quality gate on `main` is not present |
| Structured logging / centralized logs | Partial | Structured JSON logging is implemented; Grafana Loki + Grafana deployment remains pending |
| Production metrics/alerts | Needs improvement | No first-class metrics surface for key degradation/security states |

## Blocker: ambiguous review side-effect reconciliation

For approved retain requests and rejected recalled memories, the router protects non-idempotent Hindsight operations using these states:

```text
pending/postponed
-> review_side_effect_started
-> Hindsight side effect
-> review_side_effect_completed
-> finalize
```

If Hindsight returns a definite failure, the previous review state can be restored safely.

If the outcome is ambiguous (for example timeout, network failure, or process failure after Hindsight may have committed), the item remains in `review_side_effect_started`. This correctly prevents automatic replay, but there is currently no admin transition to reconcile the frozen item after an operator verifies Hindsight state.

Required resolution:

```text
review_side_effect_started
├─ confirmed applied     -> review_side_effect_completed -> finalize
└─ confirmed not applied -> postponed -> normal retry path
```

Both transitions should require the expected quarantine snapshot/hash and append explicit audit events.

## Blocker: scanned image is not guaranteed to be the published image

The current publish workflow performs:

```text
container job:
  build image A
  scan image A

publish job:
  build image B -> GHCR
  build image C -> Docker Hub
  sign/attest B and C
```

Therefore the image that passes Trivy is not guaranteed to be byte-identical to either published image.

The Dockerfile also runs `apk upgrade --no-cache`, so two builds from the same source commit can consume different mutable Alpine repository state even though the base image is digest-pinned.

Required target:

```text
source commit
-> build once
-> immutable OCI artifact/digest
-> scan exact artifact
-> publish exact artifact to both registries
-> verify digest identity
-> sign/attest exact published digest
```

## Provenance source mismatch

The default and example writer registries identify their source as `application`, but `RouterPolicy.retain()` and `RouterPolicy.recall()` currently default their runtime source argument to `openclaw`, and HTTP dispatch does not override it.

This does not bypass policy enforcement, but it produces stale product-specific provenance in injected metadata and quarantine records.

Target: derive the provenance source from the resolved writer/registry policy or use an explicitly agent-neutral runtime source.

## SonarQube Community

Add SonarQube Community as a static quality gate on `main`. Keep the existing CI/security gates; SonarQube is an additional maintainability/code-quality signal rather than a replacement for them.

## Structured logging and centralized logs

Structured JSON application logging is implemented. Centralizing the stream with Grafana Loki + Grafana remains pending.

Logging must expose stable machine-queryable fields such as request ID, event, operation, writer/bank identity where safe, status/error code, and duration while never logging request bodies, recalled memory content, credentials, secrets, or decrypted quarantine payloads.

Use Loki/Grafana for searchable retention, dashboards, and alerts around authentication failures, Hindsight degradation, quarantine admission/capacity failures, rate limiting, sweeper failures, and unresolved review side effects.

Metrics and tracing remain separate follow-up concerns rather than being coupled to the logging implementation.

## Health and operational telemetry

Health endpoint semantics are now complete:

```text
/health/live  -> router process/event-loop liveness only
/health/ready -> router quarantine storage + Hindsight /health
/health       -> exact alias of /health/ready
/ready        -> deprecated alias of /health/ready
```

The readiness checks run router storage and Hindsight health concurrently. Success returns the validated Hindsight `/health` JSON unchanged; either dependency failing returns `503 {"status":"unhealthy"}`. All health endpoints are unauthenticated.

Operational telemetry is still incomplete. Recommended metrics/alerts include:

- Hindsight availability and latency;
- degraded recall bank count;
- quarantine utilization and admission failures;
- Hindsight and quarantine rate-limit rejects;
- review items in `review_side_effect_started`;
- maintenance/sweeper failures;
- request count, latency, and status by route class.

An alert on any sustained `review_side_effect_started` item is especially important until explicit reconciliation exists.

Structured logs in this PR intentionally do not add per-request events for quarantine 413/429/507 admission failures, general 429 rate-limit rejections, or the age/count of `review_side_effect_started` items. Those signals require counters and gauges in the metrics/alerts follow-up so sustained magnitude is observable without creating request-amplified logs.

## Review order

Work through unresolved items in this order:

1. ambiguous review side-effect reconciliation;
2. build-once / scan-once / publish-same-artifact;
3. provenance source correction;
4. SonarQube Community gate;
5. deploy Grafana Loki/Grafana for the completed structured JSON log stream;
6. production metrics and alerts.

Update this checklist as each item is resolved and keep the runtime diagrams in the architecture document aligned with the implemented behavior.
