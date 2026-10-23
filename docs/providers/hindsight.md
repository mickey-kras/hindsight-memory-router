# Hindsight upstream

[Documentation](../README.md) | [Repository](../../README.md)

Hindsight is the only memory backend implemented by Memory Router today.

Current topology:

```text
OpenClaw (Hindsight plugin) -> Memory Router -> Hindsight
```

Default endpoint:

```text
http://hindsight:8888
```

Override the endpoint with `HINDSIGHT_BASE_URL`.
The value must be an absolute HTTP(S) URL without credentials, query, or fragment.
Invalid URLs fail startup.
Path prefixes do not change.
Set `HINDSIGHT_API_KEY` when the Hindsight deployment uses authentication.

Upstream requests send `Accept-Encoding: identity`. Responses must omit `Content-Encoding` or use `identity`. The router rejects other encodings before it decodes the body. Thus, decompression cannot bypass the response-size limits.

The default HTTP endpoint is for an isolated Docker network shared only by Memory Router and Hindsight.
Plaintext `http` upstream URLs fail startup unless the host is private.
Private hosts include RFC1918/link-local addresses, loopback, `*.internal`, and single-label Docker service names.
Exempt hosts keep the `insecure-hindsight-transport` startup warning.
Set `HINDSIGHT_REQUIRE_SECURE_TRANSPORT=true` to make HTTPS mandatory for every upstream. This is important when you send `HINDSIGHT_API_KEY`.

## Facade policy

- `memory_router/facade_routes.py` holds the route allowlist. `openapi/openclaw.json` is the contract.
- In legacy shared-token mode (`MEMORY_ROUTER_TOKEN`), `{bank_id}` is a writer ID resolved to its configured write bank. In principal mode (`MEMORY_ROUTER_PRINCIPALS`), it is the literal target bank, and the bearer token must grant the requested operation on that bank.
- All GET operations use recall quotas. This includes `stats?refresh=true`. Reflect, dry-run extract, and dry-run refresh also use recall quotas. Other writes use retain quotas.
- Bodies use `MEMORY_ROUTER_MAX_BODY_BYTES` (default: 1 MiB). Retain, recall, and dry-run extract have stricter limits.
- Request bodies, queries, native recall results and supplemental fields, and facade responses share four process worker slots. The queue has a limit.

  | Scan | Budget |
  | --- | --- |
  | Request body | 5 seconds |
  | Native recall result | 5 seconds |
  | Query | 256 pairs, 10 seconds |
  | Response | 256 KiB, 8,192 fields, 30 seconds |

  A worker stops one second after its budget ends. A caller waits a maximum of one more second.
- A request worker, capacity, hard timeout, or shutdown failure returns `503 request_scan_unavailable`. A read-response worker, capacity, or scan-limit failure returns `503 facade_scan_unavailable`. Both include `Retry-After: 1`. After a successful upstream facade write, a response-scan failure returns `502 hindsight_response_scan_unavailable` without `Retry-After`. Operational scanner failures do not quarantine content. Request scanner findings keep their existing behavior: block or quarantine.
- Native retain acknowledgments must be JSON objects and pass the same bounded full-response scan, including numeric leaf spellings. The router keeps safe synchronous and asynchronous acknowledgments, operation IDs, usage, and additive fields.
- The router removes unknown query parameters before scanning.

The router denies and quarantines these routes: webhooks, file transfer, import, export, metrics, provider-credential LLM health probes, cross-writer listings, and deprecated upstream routes.

## Failure mapping

`HINDSIGHT_TIMEOUT_MS` must be positive.

| Hindsight result | Router response |
| --- | --- |
| Timeout | `504 hindsight_timeout` |
| Facade 4xx except 401/403 | Same status, sanitized `hindsight_http_error` |
| Facade response over 256 KiB | `502 hindsight_response_too_large` |
| Native retain acknowledgment that is not a JSON object | `502 hindsight_invalid_response` |
| Native retain acknowledgment or post-write facade response scanner unavailable or more than the scan limit | `502 hindsight_response_scan_unavailable` |
| Unsafe native retain acknowledgment or facade response | `502 hindsight_unsafe_response` |
| Unexpected 2xx status or disallowed empty success body | `502 hindsight_invalid_response` |
| Failure of a request scanner worker, busy capacity, hard timeout, or shutdown | `503 request_scan_unavailable` |
| Native recall-result or supplemental scanner worker failure, busy capacity, hard timeout, or shutdown | `503 recall_scan_unavailable` |
| Failure of a read-response facade scanner worker, busy capacity, or a field or time limit | `503 facade_scan_unavailable` |
| Redirect, 401/403, 5xx, network, or malformed response | Typed 502 |

The router never returns upstream error response bodies.

A failed native retain acknowledgment check does not show if the write completed.
Definite upstream HTTP 4xx rejection does not carry this warning.
These post-write errors tell callers to examine the status before a retry.
They omit `Retry-After` and never retry or queue the retain for replay.
Scanner findings are not a new retain request.

A facade response-scan outage after a successful upstream write carries the same uncertainty warning.
It also has no `Retry-After` or replay.
Request-scan failures occur before the upstream write and keep their existing `503` behavior.

Optional bodies treat no body and JSON `null` the same. Mandatory bodies must be JSON objects. Bodyless upstream requests omit `Content-Type`.

A typed recall failure affects only the Hindsight read bank that failed.
If all configured read banks fail, recall returns empty results.
Unexpected application or database failures still propagate.
The router does not show them as Hindsight degradation.

## Consumption limits

Retain and recall have separate per-writer and global sliding-window budgets. Request bounds return `413`. Quota exhaustion returns `429 hindsight_rate_limited` with `Retry-After`.

All router replicas share the PostgreSQL-backed limits. Authenticated requests use quota before the content scan. Thus, blocked or quarantined scans, upstream failures, and response-scan failures count. Unknown writers and cheap structural failures do not.

The router supports no other memory backends.


