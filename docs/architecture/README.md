# Architecture

Canonical model: [`workspace.dsl`](workspace.dsl)  
Interactive architecture: [Structurizr site](https://mickey-kras.github.io/hindsight-memory-router/)

C1–C3, dynamic, and deployment views are architecture-as-code maintained in `workspace.dsl`. Structurizr validates and renders that model; it does not infer architecture from Python. Architecture-affecting runtime changes must update the DSL in the same PR. Files under `generated/` are generated; do not hand-edit them.

Dynamic views document distinct workflows rather than API inventory. Simple facade endpoints such as health/version stay in the structural/API documentation; operations with materially different routing, policy, security, or review behavior get a dynamic view. A C4 code-level view is intentionally not generated because it would be implementation-specific and does not currently add useful architectural information beyond C3.

## C1 — System Context

Who uses Memory Router and which external systems it talks to.

![C1 — System Context](generated/SystemContext.svg)

## C2 — Containers

Runtime processes and data stores.

![C2 — Containers](generated/Containers.svg)

## C3 — Components

Responsibilities inside Memory Router API.

![C3 — Components](generated/Components.svg)

## Dynamic views

- [Retain](generated/Retain.svg)
- [Recall](generated/Recall.svg)
- [Compatibility operations](generated/CompatibilityOperations.svg) — shared flow for supported bank/config/mental-model/reflect operations used by OpenClaw.
- [Quarantine / review](generated/QuarantineReview.svg)
- [Startup / shutdown](generated/StartupShutdown.svg)

## Deployment

- [Single-node + SQLite](generated/SingleNode.svg)
- [Clustered + PostgreSQL](generated/Clustered.svg)

## View names

The interactive site uses explicit human-facing prefixes:

- `C1:`, `C2:`, `C3:` for the formal C4 hierarchy.
- `Dynamic:` for runtime interaction views.
- `Deployment:` for deployment views.

The static site also adds a persistent view selector; Structurizr's built-in quick navigation remains available with `Space`.

## Updating

```bash
make architecture
```

Requires Docker. `make architecture-site` builds the uncommitted static site used by GitHub Pages.
