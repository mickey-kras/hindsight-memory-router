# OpenClaw integration

[Documentation](../README.md) | [Repository](../../README.md)

Use the [integrations package](https://github.com/mickey-kras/hindsight-memory-router-integrations) for per-agent credentials, assigned write and read banks, and HTTPS transport. Follow its [OpenClaw setup](https://github.com/mickey-kras/hindsight-memory-router-integrations/blob/main/docs/OPENCLAW.md) after creating matching [principal grants](../security/authentication.md).

## Legacy upstream Hindsight plugin

The configuration below is for the upstream Hindsight plugin with the deprecated shared router-token mode. It is not the configuration of the per-agent plugin.

Configure the OpenClaw Hindsight plugin to connect to Memory Router:

```text
hindsightApiUrl = http://memory-router:8890
hindsightApiToken = MEMORY_ROUTER_TOKEN
dynamicBankId = false
bankId = <writer_id>
bankIdPrefix = unset
autoRecall = true
autoRetain = true
```

Writer IDs must exist in the configured Memory Router registry or their requests follow the unknown-writer quarantine policy.

Compatible clients in legacy token mode use the same values: router URL, router token, and writer ID as bank ID.

Denied: webhooks, file transfer, import, export, upstream metrics, LLM health, cross-writer listings and deprecated endpoints. The router's own opt-in metrics endpoint has separate [admin authorization](../reference/api.md).

Compatibility review covers Hindsight v1.1.0, including native memory-provider search and get.
The router still supports legacy mental-model routes.
CI and the daily upstream compatibility workflow check the latest stable release.
Review source changes before you update inventory hashes.

