import http from "node:http";

const upstream = process.env.ROUTER_UPSTREAM ?? "http://memory-router:8890";
const readMax = Number(process.env.ADMIN_READ_MAX ?? "120");
const writeMax = Number(process.env.ADMIN_WRITE_MAX ?? "30");
const windowMs = Number(process.env.ADMIN_WINDOW_MS ?? "60000");
const events = { read: [], write: [] };

function requestClass(method, path) {
  if (!path.startsWith("/admin/")) return null;
  return method === "GET" || method === "HEAD" ? "read" : "write";
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

const server = http.createServer(async (req, res) => {
  const kind = requestClass(req.method ?? "GET", req.url ?? "/");
  if (kind && !consume(kind)) {
    res.writeHead(429, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "external_admin_rate_limited" }));
    return;
  }

  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const response = await fetch(new URL(req.url ?? "/", upstream), {
      method: req.method,
      headers: req.headers,
      body: chunks.length > 0 ? Buffer.concat(chunks) : undefined,
      redirect: "manual",
    });
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "router_unavailable" }));
  }
});

server.listen(8890, "0.0.0.0");
