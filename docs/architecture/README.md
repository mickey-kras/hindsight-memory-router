# Architecture

Canonical model: [`workspace.dsl`](workspace.dsl)  
Interactive model: [GitHub Pages](https://mickey-kras.github.io/hindsight-memory-router/)

C1–C3, dynamic, and deployment views are architecture-as-code maintained in `workspace.dsl`. Structurizr validates and renders that model; it does not infer architecture from Python. Architecture-affecting runtime changes must update the DSL in the same PR. Files under `generated/` are generated; do not hand-edit them.

## C1 — System Context

Who uses Memory Router and which external systems it talks to.

![C1 — System Context](generated/structurizr-SystemContext.svg)

## C2 — Containers

Runtime processes and data stores.

![C2 — Containers](generated/structurizr-Containers.svg)

## C3 — Components

Responsibilities inside Memory Router API.

![C3 — Components](generated/structurizr-Components.svg)

## Dynamic views

- [Startup / shutdown](generated/structurizr-StartupShutdown.svg)
- [Retain](generated/structurizr-Retain.svg)
- [Recall](generated/structurizr-Recall.svg)
- [Quarantine / review](generated/structurizr-QuarantineReview.svg)

## Deployment

- [Single-node + SQLite](generated/structurizr-SingleNode.svg)
- [Clustered + PostgreSQL](generated/structurizr-Clustered.svg)

## Updating

```bash
make architecture
```

Requires Docker. `make architecture-site` builds the uncommitted static site used by GitHub Pages.
