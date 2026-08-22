# Production readiness

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
| Build/publish artifact identity | Implemented; live validation pending | Workflow builds once, scans that image, pushes it to both registries, asserts digest equality, then signs/attests |
| SonarQube Community gate | Implemented; live validation pending | `main` must pass the quality gate before publication; release tags require a successful `main` publish run for the same commit |
| Structured logging / centralized logs | Pending | Adopt structured JSON logging with Grafana Loki + Grafana |
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

## Build/publish artifact identity

The publish workflow now performs:

```text
source commit
-> build once
-> scan exact local image
-> push the same image to GHCR and Docker Hub
-> assert registry digest equality
-> sign/attest exact published digests
```

Live validation remains pending for the first successful `main` publication.

## Provenance source mismatch

The default and example writer registries identify their source as `application`, but `RouterPolicy.retain()` and `RouterPolicy.recall()` currently default their runtime source argument to `openclaw`, and HTTP dispatch does not override it.

This does not bypass policy enforcement, but it produces stale product-specific provenance in injected metadata and quarantine records.

Target: derive the provenance source from the resolved writer/registry policy or use an explicitly agent-neutral runtime source.

## SonarQube Community

SonarQube Community is an additional `main` maintainability/code-quality gate. A failed gate prevents publication and creates or updates the main-pipeline tech-debt issue. Release tags publish only commits that already completed this workflow successfully on `main`.

## Structured logging and centralized logs

Adopt structured JSON application logging and centralize logs with Grafana Loki + Grafana.

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

## Review order

Work through unresolved items in this order:

1. ambiguous review side-effect reconciliation;
2. provenance source correction;
3. validate the build/publish and SonarQube gates on the first `main` run;
4. structured JSON logging + Grafana Loki/Grafana;
5. production metrics and alerts.

Update this checklist as each item is resolved and keep the runtime diagrams in the architecture document aligned with the implemented behavior.
