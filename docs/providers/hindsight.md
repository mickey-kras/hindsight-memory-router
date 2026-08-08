# Hindsight provider

Hindsight is the currently supported Memory Router provider.

Default endpoint:

```text
http://hindsight:8888
```

Override it with `HINDSIGHT_BASE_URL`. Set `HINDSIGHT_API_KEY` when the Hindsight deployment requires authentication.

Memory Router maps writer policy to Hindsight banks and enforces separate retain/recall request bounds and quotas before provider calls. Hindsight timeout, HTTP, network, malformed-response, and response-stream failures are mapped to stable router errors; upstream response bodies are not exposed.

Provider abstraction or support for additional memory systems is not implemented in this repository yet.
