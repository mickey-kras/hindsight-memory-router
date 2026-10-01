# Production readiness

[Documentation](../README.md) | [Repository](../../README.md)

[Application log schema and safety rules](logging.md).

Track unresolved production-readiness findings here; verify status against the deployed version before using it as an acceptance checklist.

See [Architecture and runtime diagrams](../architecture/README.md) for the as-built workflows.

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
| Ambiguous review side-effect reconciliation | Implemented | Operator-verified reconciliation finalizes applied effects or postpones unapplied effects |
| Router provenance source | Implemented | Known writers use their registry source unless explicitly overridden |
| Build/publish artifact identity | Implemented; live validation pending | Workflow builds once, scans that image, pushes it to both registries, asserts digest equality, then signs/attests |
| SonarQube Community gate | Implemented; live validation pending | `main` must pass the quality gate before publication; release tags require a successful `main` publish run for the same commit |
| Structured logging / centralized logs | Partial | Structured JSON logging is implemented; Grafana Loki + Grafana deployment remains pending |
| Production metrics/alerts | Partial | Opt-in `/metrics` endpoint covers the minimum counter set; latency/utilization metrics and alert rules remain pending |

## Reconcile ambiguous review outcomes

An uncertain provider result leaves the item in `review_side_effect_started`, preventing automatic replay. Inspect Hindsight, then use the [review reconciliation procedure](quarantine-review.md#concurrency-and-interruption-recovery) with the expected snapshot and `confirmed_applied` or `confirmed_not_applied`. Reconciliation records an audit event. Never infer that a timeout means the write did not happen.

## Build/publish artifact identity

The publish workflow performs:

```text
source commit
-> build once
-> scan exact local image
-> push the same image to GHCR and Docker Hub
-> assert registry digest equality
-> sign/attest exact published digests
```

Live validation remains pending for the first successful `main` publication.

## Provenance source

Known writers use their registry `source` unless the caller explicitly supplies a source. Unknown-writer quarantine retains the `openclaw` fallback. Preserve configured sources when upgrading if audit filters depend on them.

## SonarQube Community

SonarQube Community is an additional `main` maintainability/code-quality gate. A failed gate prevents publication and creates or updates the main-pipeline tech-debt issue. Release tags publish only commits that already completed this workflow successfully on `main`.

## Structured logging and centralized logs

Structured JSON logging is done. Grafana Loki + Grafana deployment is pending.

Logging must expose stable machine-queryable fields such as request ID, event, operation, writer/bank identity where safe, status/error code, and duration while never logging request bodies, recalled memory content, credentials, secrets, or decrypted quarantine payloads.

Use Loki/Grafana for searchable retention, dashboards, and alerts around authentication failures, Hindsight degradation, quarantine admission/capacity failures, rate limiting, sweeper failures, and unresolved review side effects.

Metrics and tracing remain separate follow-up concerns rather than being coupled to the logging implementation.

## Health and operational telemetry

Health endpoints:

```text
/health/live  -> router process/event-loop liveness only
/health/ready -> router quarantine storage + Hindsight /health
/health       -> exact alias of /health/ready
/ready        -> deprecated alias of /health/ready
```

The readiness checks run router storage and Hindsight health concurrently. Unauthenticated callers receive only `{"status":"healthy"}` or `{"status":"unhealthy"}`. A recognized router token or principal can receive Hindsight's validated supported health fields; unknown fields are omitted. Either dependency failing returns `503 {"status":"unhealthy"}`. Health probes do not require authentication.

Operational telemetry is partially complete. With `MEMORY_ROUTER_METRICS_ENABLED=true`, `GET /metrics` (admin read scope, or a principal with any `quarantine.review` grant; Prometheus text format) exposes:

- authentication failures by route class;
- HTTP 429 responses by route class;
- quarantine 507 admission rejections by route class;
- failed or degraded Hindsight recall bank calls;
- maintenance/sweeper failures;
- review items in `review_side_effect_started` (gauge refreshed at scrape time).

Still recommended on top of that minimum set:

- Hindsight availability and latency;
- quarantine utilization;
- request count, latency, and status by route class.

Alert on sustained `review_side_effect_started` items so an operator can investigate and reconcile them.

Use metrics, not per-request logs, for quarantine 413/429/507 responses, general 429 responses, and aged `review_side_effect_started` items.

## Review order

Work through unresolved items in this order:

1. validate the build/publish and SonarQube gates on the first `main` run;
2. deploy Grafana Loki/Grafana for the completed structured JSON log stream;
3. production metrics and alerts (minimum counter set shipped behind the opt-in `/metrics`; latency/utilization metrics pending).

Update this checklist as each item is resolved and keep the runtime diagrams in the architecture document aligned with the implemented behavior.
