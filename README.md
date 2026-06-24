# hindsight-memory-router

[![ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/ci.yml)
[![codeql](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/codeql.yml)
[![aislop ci](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/aislop.yml/badge.svg?branch=main)](https://github.com/mickey-kras/hindsight-memory-router/actions/workflows/aislop.yml)
[![aislop score](https://badges.scanaislop.com/score/mickey-kras/hindsight-memory-router.svg)](https://scanaislop.com/mickey-kras/hindsight-memory-router)
[![docker hub](https://img.shields.io/docker/v/mickeykrasilnikov/hindsight-memory-router?label=docker%20hub)](https://hub.docker.com/r/mickeykrasilnikov/hindsight-memory-router)
[![docker pulls](https://img.shields.io/docker/pulls/mickeykrasilnikov/hindsight-memory-router)](https://hub.docker.com/r/mickeykrasilnikov/hindsight-memory-router)
[![ghcr](https://img.shields.io/badge/ghcr.io-mickey--kras%2Fhindsight--memory--router-blue)](https://github.com/mickey-kras/hindsight-memory-router/pkgs/container/hindsight-memory-router)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](https://nodejs.org)

Hindsight-compatible memory policy router for OpenClaw.

```text
OpenClaw Hindsight plugin -> memory-router -> Hindsight API
```

The router is a facade/decorator, not a second memory system.

## Why

```text
writer identity required
bank chosen by policy, not by agent
recall is ACL-filtered
unknown/suspicious input is encrypted before review
unknown Hindsight endpoints are denied and logged
```

## API surface

Allowed:

```text
GET  /health                         anonymous
GET  /version                        token required
POST /v1/default/banks/{writer}/memories
POST /v1/default/banks/{writer}/memories/recall
```

Denied by default:

```text
all other endpoints
```

The Hindsight `bank_id` path value is treated as `writer_id`. Router policy decides the real bank.

## Docker

Published images:

```text
docker.io/mickeykrasilnikov/hindsight-memory-router:latest
docker.io/mickeykrasilnikov/hindsight-memory-router:<git-sha>
ghcr.io/mickey-kras/hindsight-memory-router:latest
ghcr.io/mickey-kras/hindsight-memory-router:<git-sha>
```

## Configuration

```text
MEMORY_ROUTER_PORT=8890
MEMORY_ROUTER_TOKEN=change-me
HINDSIGHT_BASE_URL=http://hindsight:8888
HINDSIGHT_API_KEY=change-me
MEMORY_ROUTER_REGISTRY=/app/writer_registry.example.json
QUARANTINE_PUBLIC_KEY=<PEM or base64 PEM>
QUARANTINE_OBJECT_DIR=/volume1/reports/hindsight-quarantine/objects
```

OpenClaw plugin config:

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
unknown writer -> encrypted quarantine + safe review ref
suspicious content -> encrypted quarantine + safe review ref
```

Recall:

```text
known writer -> only allowed read banks
unknown writer -> empty results + encrypted quarantine ref
suspicious query -> empty results + encrypted quarantine ref
suspicious recalled result -> suppressed
```

No writer recalls `quarantine`. The `main` writer does not recall `research`.

## Quarantine

```text
raw payload -> encrypted object store
review queue -> quarantine_id + metadata only
Hindsight quarantine bank -> safe index record only
```

No original text is written to the review queue or searchable memory.

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
