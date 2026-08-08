# Environment variables

All tuning/deployment values below have built-in defaults. Environment variables are optional overrides unless marked as credentials/key material. Explicit invalid values fail startup validation.

| Variable                                   |              Built-in default | Purpose                                                         |
| ------------------------------------------ | ----------------------------: | --------------------------------------------------------------- |
| `MEMORY_ROUTER_PORT`                       |                        `8890` | HTTP listener port                                              |
| `MEMORY_ROUTER_DEPLOYMENT_MODE`            |                      `single` | `single` or `cluster`                                           |
| `MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT`  |                       `false` | Confirms external shared admin limiting in cluster mode         |
| `MEMORY_ROUTER_TOKEN`                      |                          none | Router bearer token; absent means router endpoints fail closed  |
| `MEMORY_ROUTER_ADMIN_READ_TOKEN`           |                          none | Admin read scope                                                |
| `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`         |                          none | Admin review scope                                              |
| `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`        |                          none | Admin cleanup scope                                             |
| `MEMORY_ROUTER_ADMIN_TOKEN`                |                          none | Legacy all-admin migration token                                |
| `MEMORY_ROUTER_ALLOW_ANONYMOUS`            |                       `false` | Development-only anonymous router access                        |
| `MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX`  |                         `120` | Admin read requests/window                                      |
| `MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX` |                          `30` | Admin write requests/window                                     |
| `MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS` |                       `60000` | Admin rate-limit window                                         |
| `MEMORY_ROUTER_MAX_BODY_BYTES`             |                     `1048576` | Maximum JSON request body                                       |
| `MEMORY_ROUTER_REGISTRY`                   |     `main` -> `main` registry | Optional registry JSON path                                     |
| `HINDSIGHT_BASE_URL`                       |       `http://hindsight:8888` | Hindsight endpoint                                              |
| `HINDSIGHT_API_KEY`                        |                          none | Optional Hindsight API key                                      |
| `HINDSIGHT_TIMEOUT_MS`                     |                       `10000` | Hindsight request timeout                                       |
| `HINDSIGHT_RETAIN_RATE_LIMIT_WRITER_MAX`   |                          `30` | Retain requests per writer/window                               |
| `HINDSIGHT_RETAIN_RATE_LIMIT_GLOBAL_MAX`   |                         `300` | Global retain requests/window                                   |
| `HINDSIGHT_RECALL_RATE_LIMIT_WRITER_MAX`   |                         `120` | Recall requests per writer/window                               |
| `HINDSIGHT_RECALL_RATE_LIMIT_GLOBAL_MAX`   |                        `1200` | Global recall requests/window                                   |
| `HINDSIGHT_RATE_LIMIT_WINDOW_MS`           |                       `60000` | Retain/recall quota window                                      |
| `HINDSIGHT_RETAIN_MAX_ITEMS`               |                         `100` | Retain item count bound                                         |
| `HINDSIGHT_RETAIN_MAX_CONTENT_BYTES`       |                      `524288` | Aggregate retain string-content bound                           |
| `HINDSIGHT_RECALL_MAX_QUERY_BYTES`         |                       `32768` | Recall query bound                                              |
| `HINDSIGHT_RECALL_MAX_TOKENS`              |                        `8192` | Recall `max_tokens` ceiling                                     |
| `QUARANTINE_PUBLIC_KEY`                    |                          none | RSA public key; Compose injects its generated key automatically |
| `QUARANTINE_DATABASE_URL`                  | `sqlite:./data/quarantine.db` | SQLite or PostgreSQL quarantine database                        |
| `QUARANTINE_MAX_POSTPONES`                 |                           `3` | Maximum review postpones                                        |
| `QUARANTINE_MAX_ITEM_BYTES`                |                     `1048576` | Maximum encrypted item size                                     |
| `QUARANTINE_MAX_PENDING_ITEMS`             |                        `1000` | Global pending-item capacity                                    |
| `QUARANTINE_MAX_PENDING_ITEMS_PER_WRITER`  |                          `50` | Per-writer pending capacity                                     |
| `QUARANTINE_MAX_ENCRYPTED_BYTES`           |                   `104857600` | Global encrypted-byte capacity                                  |
| `QUARANTINE_RATE_LIMIT_MAX`                |                          `30` | Per-scope quarantine writes/window                              |
| `QUARANTINE_RATE_LIMIT_GLOBAL_MAX`         |                         `300` | Global quarantine writes/window                                 |
| `QUARANTINE_DISTINCT_FAMILY_LIMIT_MAX`     |                          `10` | Distinct request families per writer/window                     |
| `QUARANTINE_REQUARANTINE_OPS_MAX`          |                        `1000` | Requarantine operations/window                                  |
| `QUARANTINE_RATE_LIMIT_WINDOW_MS`          |                       `60000` | Quarantine rate-limit window                                    |
| `QUARANTINE_ITEM_TTL_DAYS`                 |                          `30` | Pending/postponed item TTL; `0` disables                        |
| `QUARANTINE_SWEEP_INTERVAL_SECONDS`        |                        `3600` | Sweep cadence; `0` disables                                     |
| `QUARANTINE_EVENT_RETENTION_DAYS`          |                          `90` | Audit-event retention; `0` keeps forever                        |

Boolean overrides accept only `true` or `false`. Integer settings are validated as non-negative or positive according to their semantics.

Any environment variable beginning with `QUARANTINE_PRIVATE_KEY` is forbidden in the running router and causes startup to fail. The private key belongs only in authorized review tooling.
