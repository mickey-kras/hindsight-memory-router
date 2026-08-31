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

await startMockRouter(MOCK_PORT);

const server = createServer((req, res) => {
  const url = new URL(req.url, "http://ui");

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
  if (!file.startsWith(DIST)) {
    res.writeHead(403).end();
    return;
  }
  readFile(file)
    .then((content) => {
      res.writeHead(200, { "Content-Type": MIME[path.extname(file)] ?? "application/octet-stream" });
      res.end(content);
    })
    .catch(() => {
      readFile(path.join(DIST, "index.html")).then((content) => {
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(content);
      });
    });
});

server.listen(UI_PORT, "127.0.0.1", () => {
  console.log(`e2e ui on http://127.0.0.1:${UI_PORT}, mock on ${MOCK_PORT}`);
});
