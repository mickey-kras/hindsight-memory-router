# Environment variables

[Documentation](../README.md) | [Repository](../../README.md)

All tuning and deployment values below have built-in defaults.
Authentication credentials are optional. If you do not set them, authentication fails closed.
Startup validation rejects explicit invalid values.

`QUARANTINE_PUBLIC_KEY` has no default.
Only the default wrap provider, `rsa-oaep`, uses it.
`https-sidecar` uses its own provider settings.

| Variable                                   |              Built-in default | Purpose                                                         |
| ------------------------------------------ | ----------------------------: | --------------------------------------------------------------- |
| `MEMORY_ROUTER_HOST`                       |                   `127.0.0.1` | Bind address of the HTTP listener                               |
| `MEMORY_ROUTER_PORT`                       |                        `8890` | HTTP listener port                                              |
| `MEMORY_ROUTER_DEPLOYMENT_MODE`            |                      `single` | `single` or `cluster`                                           |
| `MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT`  |                       `false` | Confirms external shared admin limiting in cluster mode         |
| `MEMORY_ROUTER_METRICS_ENABLED`            |                       `false` | Expose `/metrics` (Prometheus text) behind admin read auth      |
| `MEMORY_ROUTER_TOKEN`                      |                          none | Deprecated router bearer token. The next major release removes it |
| `MEMORY_ROUTER_ADMIN_READ_TOKEN`           |                          none | Admin read scope                                                |
| `MEMORY_ROUTER_ADMIN_REVIEW_TOKEN`         |                          none | Admin review scope                                              |
| `MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN`        |                          none | Admin cleanup scope                                             |
| `MEMORY_ROUTER_ADMIN_TOKEN`                |                          none | Deprecated all-admin token. The next major release removes it   |
| `MEMORY_ROUTER_ALLOW_ANONYMOUS`            |                       `false` | Development-only anonymous router access. Only for loopback binds |
| `MEMORY_ROUTER_AUTH_FAILURE_RATE_LIMIT_MAX` |                         `120` | Authentication failures per route group (`router` or `admin`) in each window |
| `MEMORY_ROUTER_AUTH_FAILURE_RATE_LIMIT_WINDOW_MS` |                   `60000` | Authentication-failure rate-limit window in milliseconds        |
| `MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX`  |                         `120` | Admin read requests in each window                              |
| `MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX` |                          `30` | Admin write requests in each window                             |
| `MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS` |                       `60000` | Admin rate-limit window                                         |
| `MEMORY_ROUTER_MAX_BODY_BYTES`             |                     `1048576` | Maximum size of a JSON request body                             |
| `MEMORY_ROUTER_REGISTRY`                   |     `main` -> `main` registry | Optional registry JSON path                                     |
| `MEMORY_ROUTER_PRINCIPALS`                 |                          none | Path of the principal registry JSON. Sets per-agent mode        |
| `MEMORY_ROUTER_HUMAN_AUTH`                 |                          none | Optional JSON with the OIDC settings for human login. Only for principal mode |
| `HINDSIGHT_BASE_URL`                       |       `http://hindsight:8888` | Hindsight endpoint                                              |
| `HINDSIGHT_API_KEY`                        |                          none | Optional Hindsight API key                                      |
| `HINDSIGHT_REQUIRE_SECURE_TRANSPORT`       |                       `false` | Make HTTPS mandatory for all Hindsight upstreams and private hosts |
| `HINDSIGHT_TIMEOUT_MS`                     |                       `10000` | Hindsight request timeout                                       |
| `HINDSIGHT_MAX_RESPONSE_BYTES`             |                     `4194304` | Maximum upstream response bytes. Facade responses and native retain acknowledgments also have a 256 KiB scan limit |
| `HINDSIGHT_RETAIN_RATE_LIMIT_WRITER_MAX`   |                          `30` | Retain requests for each writer in each window                  |
| `HINDSIGHT_RETAIN_RATE_LIMIT_GLOBAL_MAX`   |                         `300` | Global retain requests in each window                           |
| `HINDSIGHT_RECALL_RATE_LIMIT_WRITER_MAX`   |                         `120` | Recall requests for each writer in each window                  |
| `HINDSIGHT_RECALL_RATE_LIMIT_GLOBAL_MAX`   |                        `1200` | Global recall requests in each window                           |
| `HINDSIGHT_RATE_LIMIT_WINDOW_MS`           |                       `60000` | Quota window for retain and recall                              |
| `HINDSIGHT_RETAIN_MAX_ITEMS`               |                         `100` | Maximum number of items in one retain                           |
| `HINDSIGHT_RETAIN_MAX_CONTENT_BYTES`       |                      `524288` | Aggregate retain string-content bound                           |
| `HINDSIGHT_RECALL_MAX_QUERY_BYTES`         |                       `32768` | Recall query bound                                              |
| `HINDSIGHT_RECALL_MAX_TOKENS`              |                        `8192` | Recall `max_tokens` ceiling                                     |
| `QUARANTINE_PUBLIC_KEY`                    |                          none | Necessary for `rsa-oaep` only. The private key must stay off the router host |
| `QUARANTINE_DATABASE_URL`                  | `sqlite:./data/quarantine.db` | SQLite or PostgreSQL quarantine database                        |
| `QUARANTINE_MAX_POSTPONES`                 |                           `3` | Maximum review postpones                                        |
| `QUARANTINE_MAX_ITEM_BYTES`                |                     `1048576` | Maximum encrypted item size. Must be positive                   |
| `QUARANTINE_MAX_PENDING_ITEMS`             |                        `1000` | Global pending-item capacity                                    |
| `QUARANTINE_MAX_PENDING_ITEMS_PER_WRITER`  |                          `50` | Per-writer pending capacity                                     |
| `QUARANTINE_MAX_PENDING_ITEMS_PER_BANK`    |                           `0` | Capacity of each bank for pending and postponed bank-scoped items. `0` disables it |
| `QUARANTINE_MAX_ENCRYPTED_BYTES`           |                   `104857600` | Global encrypted-byte capacity                                  |
| `QUARANTINE_RATE_LIMIT_MAX`                |                          `30` | Quarantine writes for each scope in each window                 |
| `QUARANTINE_RATE_LIMIT_GLOBAL_MAX`         |                         `300` | Global quarantine writes in each window                         |
| `QUARANTINE_DISTINCT_FAMILY_LIMIT_MAX`     |                          `10` | Distinct request families for each writer in each window        |
| `QUARANTINE_REQUARANTINE_OPS_MAX`          |                        `1000` | Requarantine operations in each window                          |
| `QUARANTINE_RATE_LIMIT_WINDOW_MS`           |                       `60000` | Quarantine rate-limit window                                    |
| `QUARANTINE_ITEM_TTL_DAYS`                 |                          `30` | TTL of pending and postponed items. `0` disables it             |
| `QUARANTINE_SWEEP_INTERVAL_SECONDS`        |                        `3600` | Sweep cadence. `0` disables the sweeper                         |
| `QUARANTINE_EVENT_RETENTION_DAYS`          |                          `90` | Audit-event retention. `0` keeps events forever                 |
| `QUARANTINE_EVENT_EXPORT_PATH`             |                        unset | JSONL file that gets audit events before retention pruning      |
| `QUARANTINE_WRAP_PROVIDER`                 |                    `rsa-oaep` | DEK wrap provider: `rsa-oaep` or `https-sidecar`                |
| `QUARANTINE_WRAP_SIDECAR_URL`              |                       unset | Base URL of the wrap sidecar. HTTPS only, or HTTP on loopback   |
| `QUARANTINE_WRAP_SIDECAR_TOKEN`            |                       unset | Optional bearer token for the wrap sidecar                      |
| `QUARANTINE_WRAP_SIDECAR_TIMEOUT_MS`       |                        `5000` | Timeout of the single wrap call. Maximum `60000`                |
| `QUARANTINE_WRAP_SIDECAR_NAME`             |               `https-sidecar` | Provider name in envelope metadata. Format: `[A-Za-z0-9._-]{1,64}` |
| `QUARANTINE_WRAP_SIDECAR_VERSION`          |                           `1` | Provider version recorded in envelope metadata                  |
| `QUARANTINE_WRAP_SIDECAR_WRAPPED_KEY_BYTES` |                        `512` | Maximum wrapped-DEK size. It sets the 413 size charge           |

The router binds `127.0.0.1` by default.
Set `MEMORY_ROUTER_HOST` to expose it on other interfaces. `MEMORY_ROUTER_ALLOW_ANONYMOUS=true` fails startup when the bind address is not loopback.

Boolean overrides accept only `true` or `false`. The router validates integer settings as non-negative or positive, as each setting specifies.

With `QUARANTINE_WRAP_PROVIDER=rsa-oaep` (the default), startup must have `QUARANTINE_PUBLIC_KEY`.
The value can be PEM or base64-encoded PEM.
`QUARANTINE_WRAP_PROVIDER=https-sidecar` does not use this value.
For `.env`/Compose, use base64-encoded PEM.
Use raw multi-line PEM only for direct injection into a non-Compose process environment.

Generate the matching private key on a trusted admin machine.
Never copy that private key to the router host.

Any environment variable beginning with `QUARANTINE_PRIVATE_KEY` causes router startup to fail.
Any `QUARANTINE*` variable containing `UNWRAP` also causes startup to fail.
Do not set these variables in the running router.
Unwrap endpoints and private-key material must never reach the router process.
Unwrap occurs only in the offline review tool.

