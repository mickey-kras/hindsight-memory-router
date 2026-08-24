# OpenClaw integration

OpenClaw's Hindsight plugin is the currently supported Memory Router client integration.

Current topology:

```text
OpenClaw (Hindsight plugin) -> Memory Router -> Hindsight
```

Point the OpenClaw Hindsight plugin at Memory Router instead of directly at Hindsight:

```text
hindsightApiUrl = http://memory-router:8890
hindsightApiToken = MEMORY_ROUTER_TOKEN
dynamicBankId = false
bankId = <writer_id>
bankIdPrefix = unset
autoRecall = true
autoRetain = true
enableKnowledgeTools = false initially
```

Writer IDs must exist in the configured Memory Router registry or their requests follow the unknown-writer quarantine policy.

Any agent that speaks the bank-scoped Hindsight HTTP API can use Memory Router the same way: point it at the router URL with a router token and use the writer ID as the bank ID. Endpoints outside the facade surface (webhooks, file transfer, import/export, metrics, cross-writer listings) remain denied.
