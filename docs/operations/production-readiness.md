# Production readiness

[Documentation](../README.md) | [Repository](../../README.md)

[Application log schema and safety rules](logging.md).

This document tracks unresolved production-readiness findings.
Before you use this acceptance checklist, compare their status with the deployed version.

See [Architecture and runtime diagrams](../architecture/README.md) for the as-built workflows.

## Current status

| Area | Status | Note |
| --- | --- | --- |
| Request parsing and bounds | Ready | Strict JSON, size and depth bounds, schema validation |
| Authentication | Ready | Router and scoped admin auth fail closed |
| Retain security boundary | Ready | Full scan of strings and keys before the provider call |
| Recall security boundary | Ready | Scan of requests and results, and suppression during quarantine degradation |
| Quarantine encryption | Ready | Public-key-only router, AES-256-GCM payload encryption |
| Quarantine capacity, dedupe and rate limits | Ready | Atomic storage limits and request-family controls |
| Multi-bank recall degradation | Ready | Typed per-bank failure isolation |
| Provider response validation | Ready | Size, JSON, depth, finite-number and response-shape checks |
| Health and readiness contract | Ready | `/health/live` is router liveness. `/health` and `/health/ready` report healthy only with healthy router storage + Hindsight |
| Review concurrency | Ready | Snapshot checks and review claims |
| Protection against repeated review side effects | Ready | Explicit side-effect checkpoint states prevent blind replay |
| Ambiguous review side-effect reconciliation | Implemented | Reconciliation after an operator examination finalizes applied effects or postpones unapplied effects |
| Router provenance source | Implemented | Known writers use their registry source unless explicitly overridden |
| Build and publish artifact identity | Examine for the selected release | The workflow builds one time, scans that image, pushes it to both registries, asserts equal digests, and signs and attests the image |
| SonarQube Community gate | Examine for the selected release | `main` must pass the quality gate before publication. Each release tag must have a successful `main` publish run for the same commit |
| Structured logging and centralized logs | Deployment setup necessary | The router writes JSON logs. Configure a logging backend and retention |
| Production metrics and alerts | Partial | The opt-in `/metrics` endpoint covers the minimum counter set. Latency metrics, capacity-use metrics and alert rules are pending |

## Reconcile ambiguous review outcomes

An uncertain provider result leaves the item in `review_side_effect_started`.
This state prevents automatic replay.
Inspect Hindsight.
Follow the [review reconciliation procedure](quarantine-review.md#concurrency-and-interruption-recovery) with the expected snapshot and `confirmed_applied` or `confirmed_not_applied`.
Reconciliation records an audit event.
Never infer that a timeout means the write did not occur.

## Build and publish artifact identity

The publish workflow does these steps:

```text
source commit
-> build once
-> scan exact local image
-> push the same image to GHCR and Docker Hub
-> assert registry digest equality
-> sign/attest exact published digests
```

For the selected release, examine publication success, matching registry digests, signatures and attestations. See [releasing](../RELEASING.md).

## Provenance source

Known writers use their registry `source` unless the caller explicitly supplies a source. Unknown-writer quarantine retains the `openclaw` fallback. Preserve configured sources when upgrading if audit filters depend on them.

## SonarQube Community

SonarQube Community is one more `main` gate for maintainability and code quality. A failed gate prevents publication and creates or updates the technical-debt issue for the `main` pipeline. A release tag publishes only a commit that completed this workflow successfully on `main`.

## Structured logging and centralized logs

The router writes structured JSON logs. Configure a logging backend, retention, dashboards and alerts for your deployment. Grafana Loki and Grafana are one option.

Logging must expose stable fields that support machine queries.
These include request ID, event, operation, status or error code, duration, and the writer and bank identity where this is safe.
Logs must never contain request bodies, recalled memory content, credentials, secrets, or decrypted quarantine payloads.

Use Loki and Grafana for searchable retention and dashboards.
Configure alerts for authentication failures, Hindsight degradation, quarantine admission and capacity failures, rate limiting, sweeper failures, and unresolved review side effects.

Metrics and tracing are separate follow-up items. They are not part of the logging implementation.

## Health and operational telemetry

Health endpoints:

```text
/health/live  -> router process/event-loop liveness only
/health/ready -> router quarantine storage + Hindsight /health
/health       -> exact alias of /health/ready
/ready        -> deprecated alias of /health/ready
```

Readiness checks run router storage and Hindsight health checks concurrently.
Unauthenticated callers get only `{"status":"healthy"}` or `{"status":"unhealthy"}`.
A recognized router token or principal can get the validated, supported health fields of Hindsight.
The response omits unknown fields.
Failure of either dependency returns `503 {"status":"unhealthy"}`.
Health probes do not use authentication.

Operational telemetry is partially complete.
With `MEMORY_ROUTER_METRICS_ENABLED=true`, `GET /metrics` exposes the following metrics in Prometheus text format.
It must have admin read scope or a principal with a `quarantine.review` grant.

- Authentication failures by route class.
- HTTP 429 responses by route class.
- Quarantine 507 admission rejections by route class.
- Failed or degraded Hindsight recall bank calls.
- Maintenance and sweeper failures.
- Review items in `review_side_effect_started` (a gauge that the router refreshes at scrape time).

Still recommended on top of that minimum set:

- Hindsight availability and latency.
- Use of quarantine capacity.
- Request count, latency, and status by route class.

Alert on sustained `review_side_effect_started` items so an operator can investigate and reconcile them.

Use metrics for quarantine 413/429/507 responses, general 429 responses, and aged `review_side_effect_started` items.
Per-request logs do not cover these events.

## Review order

Work through unresolved items in this order:

1. Examine the publication digests, the signatures and the SonarQube gate for the selected release.
2. Configure a logging backend, retention and dashboards for the JSON log stream.
3. Configure production metrics and alerts.
   The minimum counter set is available through the opt-in `/metrics`.
   Latency metrics and capacity-use metrics are pending.

Update this checklist after you resolve each item.
Keep the runtime diagrams in the architecture document consistent with the implemented behavior.

