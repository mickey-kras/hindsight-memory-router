# OpenClaw integration

OpenClaw is one possible client of Memory Router; it is not part of the product identity or runtime architecture.

For the existing Hindsight-compatible integration, point OpenClaw at Memory Router instead of directly at Hindsight:

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
