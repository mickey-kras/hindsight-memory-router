# Memory Router UI

[Documentation](../docs/README.md) | [Repository](../README.md)

Quarantine review console for hindsight-memory-router. Static export, no backend, dark only.

- Same-origin with the router: nginx serves the static files and proxies `/admin`, `/health`, `/version` to the router. No CORS, no router changes.
- Admin tokens live in sessionStorage only. Decryption is local (WebCrypto, RSA-OAEP-SHA-256 + AES-256-GCM, RFC 8785 canonical JSON); the decryption key is imported as a non-extractable CryptoKey and never leaves the tab.

## Package

Release automation publishes `@mickey-kras/memory-router-ui` to public npm with
provenance. The package contains the built `dist/`, metadata, README and license.
It is a static application; no Node server is included.

After the [first-publication setup](../docs/RELEASING.md#npm-first-publication):

```bash
npm install --ignore-scripts @mickey-kras/memory-router-ui@<version>
# Serve node_modules/@mickey-kras/memory-router-ui/dist/ with your static host.

# Or download and extract without installing dependencies:
npm pack @mickey-kras/memory-router-ui@<version> --ignore-scripts
mkdir ui-static
tar -xzf mickey-kras-memory-router-ui-<version>.tgz -C ui-static
python3 -m http.server 8080 --bind 127.0.0.1 --directory ui-static/package/dist
```

The Python command is a local preview. Production hosting needs HTTPS and the
security headers below. Configure the router URL and allowed origin as described
under **Embedding**.

The npm tarball is byte-identical to the signed GitHub release asset. Download its
`.sigstore.json` bundle from the same release, then verify:

```bash
cosign verify-blob --bundle mickey-kras-memory-router-ui-<version>.tgz.sigstore.json \
  --certificate-identity 'https://github.com/mickey-kras/hindsight-memory-router/.github/workflows/publish.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  mickey-kras-memory-router-ui-<version>.tgz
```

The former unscoped package/asset `memory-router-ui-<version>.tgz` becomes
`@mickey-kras/memory-router-ui` / `mickey-kras-memory-router-ui-<version>.tgz`.
Update download scripts and installed paths; older releases keep their original names.

### Embedding

Default is same-origin (the nginx deployment below) and needs no configuration.
A host product may inject configuration before the app script loads:

```html
<script src="/memory-router-ui.config.js"></script>
```

```js
// memory-router-ui.config.js
window.__MEMORY_ROUTER_UI_CONFIG__ = {
  baseUrl: "https://router.internal.example", // opt-in; default is same-origin
  productName: "Acme Memory",                 // opt-in header title
  theme: { accent: "#38bdf8" },               // opt-in hex overrides: accent, background, foreground
  chrome: { header: true, branding: false },  // opt-in embedding flags (default: both true)
};
```

The documented CSP is `script-src 'self'`: serve the config as an external
file like above (or pin an inline snippet with a CSP hash); an inline
`<script>` is blocked.

- `baseUrl`: absolute http(s) URL without credentials, query, or fragment.
  Cross-origin use puts CORS and the admin session boundary on the host; the
  router stays unchanged.
- `theme`: hex-color overrides mapped to CSS variables (`accent` to
  `--mr-accent`, `background` to `--mr-bg`, `foreground` to `--mr-fg`).
- `chrome`: `header: false` hides the whole header bar (host renders its own
  chrome; queue actions then need host wiring), `branding: false` hides only
  the product name and status dot.

Unknown keys and malformed values fail closed at startup. In the default
`auth: "token"` mode, admin tokens live in sessionStorage only.

### Authenticated host and compact layout

```js
window.__MEMORY_ROUTER_UI_CONFIG__ = {
  auth: "host",
  baseUrl: "https://console.example/router", // must match the page origin
  chrome: { embed: true },
};
```

`auth: "host"` skips Connect and never accesses `mr-admin-tokens`. Requests
use the host session, send no UI-generated bearer header, and reject redirects.
Omit `baseUrl` for the page origin without a path prefix. Cross-origin host mode
is rejected. A 401 clears the displayed queue, item and cleanup state; sign in
through the host and Refresh. Errors never fall back to stored admin tokens.

The host/proxy must:

- Authenticate each request and authorize each action before injecting the
  existing router read, review or cleanup bearer credential. A read-only operator
  must not gain review or cleanup access.
- Protect cookie-authenticated mutations against CSRF, for example by validating
  the exact trusted Origin and rejecting missing/opaque/foreign origins. An
  equivalent established CSRF mechanism is also valid. Same-origin UI config is
  not CSRF protection.
- Keep router credentials server-side, strip browser-supplied Authorization,
  avoid returning credentials in errors, and leave router scope checks enabled.

This package adds no router cookie authentication or new token type. Deploy it
behind that boundary; the standalone nginx example below does not provide it.

`chrome.embed: true` removes the full-viewport shell and product header while
keeping Refresh, Cleanup and review actions. Token mode also keeps Disconnect.
It works independently of `auth` and overrides `chrome.header: false` for the
action toolbar. With embed omitted, existing header/branding behavior is unchanged.

### Version and crypto contract

Package semver tracks the router admin API contract it consumes: bump minor
when the consumed contract grows, patch for UI-only fixes. The console consumes
`/version` and the `/admin/quarantine/*` endpoints.

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

