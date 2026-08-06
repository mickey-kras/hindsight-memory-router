import { Buffer } from "node:buffer";
import http from "node:http";
import process from "node:process";

const upstreamHost = "memory-router";
const upstreamPort = 8890;
const readMax = Number(process.env.ADMIN_READ_MAX ?? "120");
const writeMax = Number(process.env.ADMIN_WRITE_MAX ?? "30");
const windowMs = Number(process.env.ADMIN_WINDOW_MS ?? "60000");
const maxBodyBytes = 1_048_576;
const events = { read: [], write: [] };

function requestClass(method, path) {
  if (!path.startsWith("/admin/")) return null;
  return method === "GET" || method === "HEAD" ? "read" : "write";
}

function isAllowedPath(path) {
  return (
    path === "/health" ||
    path === "/ready" ||
    path === "/version" ||
    path.startsWith("/v1/default/banks/") ||
    path.startsWith("/admin/quarantine/")
  );
}

function consume(kind) {
  const now = Date.now();
  const cutoff = now - windowMs;
  events[kind] = events[kind].filter((at) => at > cutoff);
  const max = kind === "read" ? readMax : writeMax;
  if (events[kind].length >= max) return false;
  events[kind].push(now);
  return true;
}

function sendJson(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

const server = http.createServer((req, res) => {
  const method = req.method ?? "GET";
  const path = req.url ?? "/";
  if (!isAllowedPath(path)) {
    sendJson(res, 404, { error: "proxy_path_not_allowed" });
    return;
  }

  const kind = requestClass(method, path);
  if (kind && !consume(kind)) {
    sendJson(res, 429, { error: "external_admin_rate_limited" });
    return;
  }

  let bodyBytes = 0;
  const upstream = http.request(
    {
      host: upstreamHost,
      port: upstreamPort,
      method,
      path,
      headers: {
        ...(req.headers.authorization
          ? { authorization: req.headers.authorization }
          : {}),
        ...(req.headers["content-type"]
          ? { "content-type": req.headers["content-type"] }
          : {}),
      },
    },
    (upstreamResponse) => {
      res.writeHead(upstreamResponse.statusCode ?? 502, {
        "content-type":
          upstreamResponse.headers["content-type"] ?? "application/json",
      });
      upstreamResponse.pipe(res);
    },
  );

  upstream.on("error", () => {
    if (!res.headersSent) sendJson(res, 502, { error: "router_unavailable" });
    else res.destroy();
  });

  req.on("data", (chunk) => {
    bodyBytes += Buffer.byteLength(chunk);
    if (bodyBytes > maxBodyBytes) {
      upstream.destroy();
      if (!res.headersSent) sendJson(res, 413, { error: "payload_too_large" });
      req.destroy();
      return;
    }
    upstream.write(chunk);
  });
  req.on("end", () => upstream.end());
  req.on("error", () => upstream.destroy());
});

server.listen(8890, "0.0.0.0");
