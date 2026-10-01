# OpenClaw integration

[Documentation](../README.md) | [Repository](../../README.md)

Use the [Memory Router integrations package](https://github.com/mickey-kras/hindsight-memory-router-integrations) for per-agent credentials, assigned write/read banks and HTTPS transport. Follow its [OpenClaw setup](https://github.com/mickey-kras/hindsight-memory-router-integrations/blob/main/docs/OPENCLAW.md) after creating matching [principal grants](../security/authentication.md).

## Legacy upstream Hindsight plugin

The configuration below is for the upstream Hindsight plugin with the deprecated shared router-token mode. It is not the per-agent Memory Router plugin configuration.

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

Compatible clients in legacy token mode use the same values: router URL, router token, and writer ID as bank ID.

Denied: webhooks, file transfer, import/export, upstream metrics, LLM health, cross-writer listings and deprecated endpoints. The router's own opt-in metrics endpoint has separate [admin authorization](../reference/api.md).
