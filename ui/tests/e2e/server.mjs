// E2E server: serves the built UI from dist/ and proxies /admin, /health,
// /version to the mock router - the same shape as the production nginx
// (static UI same-origin with the router admin API, no CORS).

import { createServer } from "node:http";
import { access, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { startMockRouter } from "./mockRouter.mjs";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "../..");
const DIST = path.join(ROOT, "dist");
const DIST_PREFIX = `${DIST}${path.sep}`;
const UI_PORT = Number(process.env.UI_PORT ?? 4173);
const MOCK_PORT = Number(process.env.MOCK_PORT ?? 8899);

try {
  await access(path.join(DIST, "index.html"));
} catch {
  throw new Error("ui/dist is missing; run npm run build before npm run test:e2e");
}

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

const mock = await startMockRouter(MOCK_PORT);

const server = createServer((req, res) => {
  const url = new URL(req.url, "http://ui");

  if (url.pathname.startsWith("/host/admin/")) {
    const fail = (status, error) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error, message: error }));
    };
    const session = (req.headers.cookie ?? "").split("; ").find((cookie) => cookie.startsWith("host-session="))?.split("=")[1];
    if (session !== "operator" && session !== "reader") return fail(401, "host_session_required");
    const pathname = url.pathname.slice("/host".length);
    const scope = req.method === "GET" ? "read" : pathname === "/admin/quarantine/cleanup" ? "cleanup" : "review";
    if (scope !== "read" && session !== "operator") return fail(403, "host_permission_denied");
    // Test host uses exact Origin validation, including rejecting a missing Origin.
    // UI same-origin configuration alone cannot enforce this boundary.
    if (scope !== "read" && req.headers.origin !== `http://127.0.0.1:${UI_PORT}`) return fail(403, "host_csrf_rejected");
    if (req.headers.authorization) return fail(400, "browser_bearer_rejected");
    fetch(`http://127.0.0.1:${MOCK_PORT}${pathname}${url.search}`, {
      method: req.method,
      headers: { authorization: `Bearer ${mock.tokens[scope]}`, "content-type": "application/json" },
      body: ["GET", "HEAD"].includes(req.method) ? undefined : req,
      duplex: "half",
      redirect: "error",
    }).then(async (upstream) => {
      res.writeHead(upstream.status, { "Content-Type": "application/json" });
      res.end(Buffer.from(await upstream.arrayBuffer()));
    }).catch(() => fail(502, "host_upstream_unavailable"));
    return;
  }

  if (
    url.pathname.startsWith("/admin") ||
    url.pathname.startsWith("/health") ||
    url.pathname.startsWith("/version")
  ) {
    const proxy = new Request(`http://127.0.0.1:${MOCK_PORT}${url.pathname}${url.search}`, {
      method: req.method,
      headers: { authorization: req.headers.authorization ?? "", "content-type": "application/json" },
      body: ["GET", "HEAD"].includes(req.method) ? undefined : req,
      duplex: "half",
    });
    fetch(proxy).then(async (upstream) => {
      res.writeHead(upstream.status, { "Content-Type": "application/json" });
      res.end(Buffer.from(await upstream.arrayBuffer()));
    });
    return;
  }

  const rel = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const file = path.join(DIST, rel);
  if (!file.startsWith(DIST_PREFIX)) {
    res.writeHead(403).end();
    return;
  }
  readFile(file)
    .then((content) => {
      res.writeHead(200, { "Content-Type": MIME[path.extname(file)] ?? "application/octet-stream" });
      res.end(content);
    })
    .catch(() => {
      readFile(path.join(DIST, "index.html"))
        .then((content) => {
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(content);
        })
        .catch(() => {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end("ui/dist/index.html is unavailable");
        });
    });
});

server.listen(UI_PORT, "127.0.0.1", () => {
  console.log(`e2e ui on http://127.0.0.1:${UI_PORT}, mock on ${MOCK_PORT}`);
});
