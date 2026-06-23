# hindsight-memory-router

[![ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![codeql](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](https://nodejs.org)
[![aislop](https://badges.scanaislop.com/score/mickey-kras/hindsight-memory-router.svg)](https://scanaislop.com)

Hindsight-compatible memory policy router for OpenClaw and future agent platforms.

It sits between agents and Hindsight:

```text
OpenClaw Hindsight plugin
  -> hindsight-memory-router
      -> writer registry
      -> deterministic safety filter
      -> bank routing / recall ACL
      -> Hindsight API
```

The router is a facade/decorator, not a second memory system.

## Why

Direct agent access to a long-term memory API is risky.

This router adds:

```text
writer identity required
bank chosen by policy, not by agent
unknown writers go to review queue
suspicious content goes to review queue
recall is ACL-filtered
unknown Hindsight endpoints are denied and logged
```

## Status

Early prototype.

Do not use as the only protection layer until unit, contract, Docker, and live smoke tests pass in your environment.

## API surface v0

Allowed:

```text
GET  /health
GET  /version
POST /v1/default/banks/{writer_id}/memories
POST /v1/default/banks/{writer_id}/memories/recall
```

Denied by default:

```text
all other endpoints
```

The path value called `bank_id` by the Hindsight API is treated here as `writer_id`.

Example:

```text
POST /v1/default/banks/main/memories
```

means:

```text
writer_id = main
```

The router decides the real target bank from `writer_registry.example.json`.

## Local development

Requires Node.js 22+.

```bash
npm ci
npm test
npm run typecheck
npm run build
npm start
```

In another shell:

```bash
curl -fsS http://127.0.0.1:8890/health
curl -fsS http://127.0.0.1:8890/version
```

## Docker

```bash
docker build -t hindsight-memory-router:local .
docker run --rm -p 8890:8890 hindsight-memory-router:local
```

## Configuration

Environment variables:

```text
MEMORY_ROUTER_PORT=8890
MEMORY_ROUTER_TOKEN=change-me
HINDSIGHT_BASE_URL=http://hindsight:8888
HINDSIGHT_API_KEY=change-me
MEMORY_ROUTER_REGISTRY=/app/writer_registry.example.json
```

OpenClaw plugin target config:

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

## Safety model

Retain:

```text
known writer + clean content -> assigned write bank
unknown writer -> review queue
suspicious content -> review queue
```

Recall:

```text
known writer -> only allowed read banks
unknown writer -> empty results
suspicious query -> empty results
suspicious recalled result -> suppressed
```

Default read target example:

```text
main:     main, core, ops, dev, creative, personal
dev:      dev, core
creative: creative, core
ops:      ops, core
research: research, core
```

No writer recalls `quarantine`. The `main` writer does not recall `research`.

## Review queue

Suspicious/unknown content is written as JSONL review records, not retained into Hindsight.

Default path:

```text
/volume1/reports/hindsight-review/review.jsonl
```

## Checks

```bash
npm run format:check
npm run lint
npm test
npm run typecheck
npm run security:audit
npm run aislop:ci
```

## License

MIT
