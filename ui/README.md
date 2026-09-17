# Memory Router UI

Quarantine review console for hindsight-memory-router. Static export, no backend, dark only.

- Same-origin with the router: nginx serves the static files and proxies `/admin`, `/health`, `/version` to the router. No CORS, no router changes.
- Admin tokens live in sessionStorage only. Decryption is local (WebCrypto, RSA-OAEP-SHA-256 + AES-256-GCM, RFC 8785 canonical JSON); the decryption key is imported as a non-extractable CryptoKey and never leaves the tab.

## Package

`memory-router-ui` ships as a signed tarball (`memory-router-ui-<version>.tgz`
plus a cosign sign-blob bundle) attached to each router GitHub release; it is
not on npm. Packaging is registry-agnostic: the same `npm pack` artifact can be
republished to npm or GitHub Packages later without changes. The tarball
contains only `dist/` plus `README.md`/`LICENSE`; verify with
`npm run test:package` or:

```bash
cosign verify-blob --bundle memory-router-ui-<version>.tgz.sigstore.json \
  --certificate-identity-regexp 'https://github.com/mickey-kras/hindsight-memory-router/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  memory-router-ui-<version>.tgz
```

### Embedding

Default is same-origin (the nginx deployment below) and needs no configuration.
A host product may inject configuration before the app script loads:

```html
<script>
  window.__MEMORY_ROUTER_UI_CONFIG__ = {
    baseUrl: "https://router.internal.example", // opt-in; default is same-origin
    productName: "Acme Memory",                 // opt-in header title
  };
</script>
```

`baseUrl` must be an absolute http(s) URL without credentials, query, or
fragment; anything malformed fails closed at startup. Cross-origin use puts
CORS and the admin session boundary on the host; the router stays unchanged.
Unknown config keys are rejected. Admin tokens still live in sessionStorage
only; the package never bundles or persists credentials.

### Version and crypto contract

Package semver tracks the router admin API contract it consumes: bump minor
when the consumed contract grows, patch for UI-only fixes. The console consumes
`/version`, `/health`, and the `/admin/quarantine/*` endpoints.

| UI package | Router admin API | Consumed contract |
| --- | --- | --- |
| 0.2.x | main after #278/#280/#281 (first router release carrying them) | per-bank queue/stats filters, reconcile actions, provider-versioned envelope metadata |
| 0.1.x | 0.1.x releases | internal only, never published |

Decryption support is RSA-OAEP-SHA256 key wrap only. Envelopes carrying a
`provider` block (pluggable key wrap) are refused before any key unwrap,
matching the router's own `decrypt_envelope`; unwrapping those requires the
matching review-tool provider.

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
