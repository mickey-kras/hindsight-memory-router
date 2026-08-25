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

Other Hindsight API clients use the same values: router URL, router token, and writer ID as bank ID.

Denied: webhooks, file transfer, import/export, metrics, and cross-writer listings.
