# Architecture

[Documentation](../README.md) | [Repository](../../README.md)

Canonical model: [`workspace.dsl`](workspace.dsl)  
Interactive architecture: [Structurizr site](https://mickey-kras.github.io/hindsight-memory-router/)

C1 to C3, dynamic, and deployment views are architecture-as-code maintained in `workspace.dsl`. Structurizr validates and renders that model; it does not infer architecture from Python. Architecture-affecting runtime changes must update the DSL in the same PR. Files under `generated/` are generated from the DSL or the README overview generator; do not hand-edit them.

Dynamic views cover principal authorization, client coordination, routing, policy, security and review workflows. Health/version endpoints stay in the structural and API references. The model stops at C3.

## README overview

Each README uses the same topology and highlights its own repository, with separate light/dark SVG assets. Generate this repository's pair with `python3 scripts/architecture-overview.py` (also run by `make architecture`). Export the integrations pair directly into that repository:

```sh
python3 scripts/architecture-overview.py --repository integrations --output-dir ../hindsight-memory-router-integrations/docs/architecture
```

Only each repository's own pair is committed there. The diagrams deliberately omit deployment details; README `<picture>` elements select the theme and provide a light fallback.

## Overview and detailed views

<a href="https://mickey-kras.github.io/hindsight-memory-router/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="generated/overview-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="generated/overview-light.svg">
    <img alt="Agents use Integrations, Memory Router, and Hindsight; Memory Router and its encrypted quarantine are highlighted." src="generated/overview-light.svg">
  </picture>
</a>

- [C1: System Context](https://mickey-kras.github.io/hindsight-memory-router/#SystemContext): users and external systems.
- [C2: Containers](https://mickey-kras.github.io/hindsight-memory-router/#Containers): runtime processes and data stores.
- [C3: Components](https://mickey-kras.github.io/hindsight-memory-router/#Components): responsibilities inside the API.

## Dynamic views

- [Principal authorization](https://mickey-kras.github.io/hindsight-memory-router/#PrincipalAuthorization): authenticate credentials and check bank/scope grants before memory access.
- [Integration reads](https://mickey-kras.github.io/hindsight-memory-router/#IntegrationReads): client fan-out, shared budget, partial results, and authorization failure handling.
- [Retain queue / replay](https://mickey-kras.github.io/hindsight-memory-router/#RetainReplay): transient outage queuing and current write-bank checks.
- [Retain](https://mickey-kras.github.io/hindsight-memory-router/#Retain)
- [Recall](https://mickey-kras.github.io/hindsight-memory-router/#Recall)
- [Compatibility operations](https://mickey-kras.github.io/hindsight-memory-router/#CompatibilityOperations): shared flow for supported bank/config/mental-model/reflect operations used by the integrations.
- [Quarantine / review](https://mickey-kras.github.io/hindsight-memory-router/#QuarantineReview): browser or CLI decryption and decision outcomes.
- [Quarantine recovery](https://mickey-kras.github.io/hindsight-memory-router/#QuarantineRecovery): verified reconciliation after ambiguous side effects.
- [Startup / shutdown](https://mickey-kras.github.io/hindsight-memory-router/#StartupShutdown)

### Implementation boundaries

Principal-mode requests authorize the explicit bank and operation scope. Legacy writer mode maps writer IDs to banks; its server-side recall fan-out is separate from client-side multi-bank coordination. The client mapping never grants server access.

Integration retain queues hold **plaintext transcripts on the agent host**. They are separate from the router's encrypted quarantine. OpenClaw and the MCP adapter use the shared coordinator where configured; coding-agent adapters also have harness-specific capture and cursor behavior.

Review approval of a retained request rechecks its original destination and current grant, then writes to Hindsight. Approval of a recalled memory allows that reviewed memory without another retain; rejection invalidates it. Rejecting a retained request does not write it. Postpone defers review. After an ambiguous side effect, an operator verifies Hindsight and reconciles the current snapshot; the router does not blindly replay the operation. See [review operations](../operations/quarantine-review.md).

The browser console decrypts RSA-OAEP envelopes with WebCrypto. Provider-wrapped envelopes require review tooling configured for the matching provider; see [quarantine review](../operations/quarantine-review.md).

These flows are grounded in `memory_router/principal_gate.py`, `request_dispatch.py`, `policy.py`, and `admin.py`; client flows follow the integrations repository's `src/shared/recall-coordinator.ts`, `retain-coordinator.ts`, and `src/mcp/server.ts`.

## Deployment

- [Single-node + SQLite](https://mickey-kras.github.io/hindsight-memory-router/#SingleNode)
- [Clustered + PostgreSQL](https://mickey-kras.github.io/hindsight-memory-router/#Clustered)

## View names

The interactive site uses explicit human-facing prefixes:

- `C1:`, `C2:`, `C3:` for the formal C4 hierarchy.
- `Dynamic:` for runtime interaction views.
- `Deployment:` for deployment views.

The static site opens on System Context when no view is linked and adds a persistent view selector; Structurizr's built-in quick navigation remains available with `Space`.

## Updating

```bash
make architecture
```

Requires Docker. `make architecture-site` builds the uncommitted static site used by GitHub Pages.

