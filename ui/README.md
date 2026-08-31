# Memory Router UI

Quarantine review console for hindsight-memory-router. Static export, no backend, dark only.

- Same-origin with the router: nginx serves the static files and proxies `/admin`, `/health`, `/version` to the router. No CORS, no router changes.
- Admin tokens live in sessionStorage only. Decryption is local (WebCrypto, RSA-OAEP-SHA-256 + AES-256-GCM, RFC 8785 canonical JSON); the decryption key is imported as a non-extractable CryptoKey and never leaves the tab.

## Develop

```bash
python3 -m pip install -r ../requirements.txt
npm ci
npm run fixtures                    # disposable local crypto fixtures
node tests/e2e/mockRouter.mjs 8899   # mock router with golden fixtures
npm run dev                          # vite proxies /admin to the mock
```

## Test

```bash
npm run test        # unit + crypto conformance against router-generated fixtures
npm run build
npm run test:e2e    # playwright, laptop + phone viewports, real envelopes via mock
```

Tests generate disposable fixtures in `tests/fixtures/` with the router's own
`memory_router/envelope.py`. Regenerate them manually after envelope-format changes:

```bash
python3 ui/tests/gen_fixtures.py
```

## Deploy

Serve `dist/` with nginx and proxy the admin API:

```nginx
server {
    listen 8080;
    root /usr/share/nginx/html;
    add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'" always;
    add_header Referrer-Policy no-referrer always;
    location /admin/  { proxy_pass http://memory-router:8890; }
    location = /health { proxy_pass http://memory-router:8890; }
    location /health/ { proxy_pass http://memory-router:8890; }
    location /version { proxy_pass http://memory-router:8890; }
}
```

Expose only through a trusted private network. Cleanup and review actions need their scoped
tokens; read-only use works with the read token alone.
