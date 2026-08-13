# Architecture

Canonical model: [`workspace.dsl`](workspace.dsl). Generated files under [`generated/`](generated/) are not hand-edited.

## System Context

[System Context](generated/structurizr-SystemContext.md)

- Current topology: OpenClaw (Hindsight plugin) → Memory Router → Hindsight.
- Hindsight is the only implemented backend.
- Review/decryption keeps the private key outside the Memory Router process.

## Container

[Container](generated/structurizr-Containers.md)

- SQLite is the single-node quarantine store.
- PostgreSQL is required for clustered quarantine/shared router rate-limit state.
- Clustered admin traffic requires an external shared rate limiter before router replicas.

## Component

[Component](generated/structurizr-Components.md)

Security gates are shown where requests/provider responses cross policy boundaries.

## Dynamic

- [Startup / shutdown](generated/structurizr-StartupShutdown.md)
- [Retain](generated/structurizr-Retain.md)
- [Recall](generated/structurizr-Recall.md)
- [Quarantine / review](generated/structurizr-QuarantineReview.md)

## Deployment

- [Single-node + SQLite](generated/structurizr-SingleNode.md)
- [Clustered + PostgreSQL](generated/structurizr-Clustered.md)

## Regenerate

```bash
make architecture
```

Requires Python, Java 21+, `curl`, and `unzip`. The command validates the DSL and regenerates committed Mermaid from the checksum-pinned Structurizr CLI release.

Architecture-affecting PRs update `workspace.dsl` and commit the refreshed generated files in the same PR.
