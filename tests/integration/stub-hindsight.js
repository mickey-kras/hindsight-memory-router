import { Buffer } from "node:buffer";
import { appendFileSync, mkdirSync } from "node:fs";
import { createServer } from "node:http";
import { dirname } from "node:path";
import process from "node:process";
import { URL } from "node:url";

const PORT = Number(process.env.PORT ?? "8888");
const LOG_PATH = process.env.STUB_HINDSIGHT_LOG ?? "/state/hindsight.jsonl";

function send(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

function record(event) {
  mkdirSync(dirname(LOG_PATH), { recursive: true });
  appendFileSync(LOG_PATH, JSON.stringify(event) + "\n", { encoding: "utf8" });
}

createServer(async (req, res) => {
  try {
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", `http://127.0.0.1:${PORT}`);

    if (method === "GET" && url.pathname === "/health") {
      return send(res, 200, { status: "healthy", service: "stub-hindsight" });
    }

    if (method === "GET" && url.pathname === "/version") {
      return send(res, 200, {
        api_version: "0.8.3",
        service: "stub-hindsight",
      });
    }

    const retain = url.pathname.match(
      /^\/v1\/default\/banks\/([^/]+)\/memories$/,
    );
    if (method === "POST" && retain) {
      const body = await readJson(req);
      const bankId = decodeURIComponent(retain[1]);
      record({ kind: "retain", bank_id: bankId, body });
      return send(res, 200, {
        success: true,
        bank_id: bankId,
        items_count: body.items?.length ?? 0,
        async: body.async ?? false,
      });
    }

    const recall = url.pathname.match(
      /^\/v1\/default\/banks\/([^/]+)\/memories\/recall$/,
    );
    if (method === "POST" && recall) {
      const body = await readJson(req);
      const bankId = decodeURIComponent(recall[1]);
      record({ kind: "recall", bank_id: bankId, body });
      return send(res, 200, {
        results: [
          {
            id: `${bankId}-stub-result`,
            text: `memory from ${bankId}`,
            type: "world",
            metadata: { bank_id: bankId },
          },
        ],
      });
    }

    return send(res, 404, { error: "not found" });
  } catch {
    return send(res, 500, { error: "internal error" });
  }
}).listen(PORT, () => {
  process.stdout.write(`stub-hindsight listening on ${PORT}\n`);
});
