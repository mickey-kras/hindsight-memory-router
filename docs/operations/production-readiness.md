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
| Review concurrency | Ready | Snapshot checks and review claims |
| Non-idempotent review side-effect protection | Ready | Explicit side-effect checkpoint states prevent blind replay |
| Ambiguous review side-effect reconciliation | Blocked | No supported transition out of `review_side_effect_started` after an ambiguous provider outcome |
| Router provenance source | Needs correction | Runtime defaults policy source to `openclaw` instead of using the agent-neutral registry source |
| Build/publish artifact identity | Blocked | Trivy scans one build; publish jobs rebuild independently before pushing/signing |
| SonarQube gate | Pending | Planned Sonar Community gate is not present |
| Provider health telemetry | Needs improvement | `/ready` checks quarantine storage only |
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

## SonarQube

The current CI/security stack includes Ruff, mypy, pytest/coverage, pip-audit, Bandit, npm audit, Gitleaks, Semgrep, Hadolint, Aislop, CodeQL, and Trivy.

The planned Sonar Community main-branch quality gate is not currently wired into CI or publishing.

## Readiness and provider telemetry

Current readiness semantics are:

```text
/health -> process is alive
/ready  -> quarantine database is reachable
```

Hindsight availability is not part of `/ready`. This is compatible with recall's deliberate partial-degradation behavior, but production operations still need a separate provider-health signal because valid retain calls cannot succeed while Hindsight is unavailable.

Recommended telemetry includes:

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
2. build-once / scan-once / publish-same-artifact;
3. provenance source correction;
4. SonarQube gate;
5. provider health telemetry;
6. production metrics and alerts.

Update this checklist as each item is resolved and keep the runtime diagrams in the architecture document aligned with the implemented behavior.
