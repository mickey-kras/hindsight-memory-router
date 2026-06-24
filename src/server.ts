import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { URL } from "node:url";
import {
  FetchHindsightGateway,
  type HindsightGateway,
} from "./hindsightClient.js";
import { RouterPolicy } from "./policy.js";
import { loadRegistry } from "./registry.js";
import { JsonlReviewQueue, type ReviewQueue } from "./reviewQueue.js";
import type { RecallBody, RetainBody, WriterRegistry } from "./types.js";

const PORT = Number(process.env.MEMORY_ROUTER_PORT ?? "8890");
const ROUTER_TOKEN = process.env.MEMORY_ROUTER_TOKEN;
const HINDSIGHT_BASE_URL =
  process.env.HINDSIGHT_BASE_URL ?? "http://hindsight:8888";
const HINDSIGHT_API_KEY = process.env.HINDSIGHT_API_KEY;
const REGISTRY_PATH = process.env.MEMORY_ROUTER_REGISTRY;

export interface CreateMemoryRouterServerOptions {
  routerToken?: string;
  registry?: WriterRegistry;
  hindsight?: HindsightGateway;
  reviewQueue?: ReviewQueue;
}

function buildPolicy(
  options: CreateMemoryRouterServerOptions = {},
): RouterPolicy {
  const registry = options.registry ?? loadRegistry(REGISTRY_PATH);
  return new RouterPolicy({
    registry,
    hindsight:
      options.hindsight ??
      new FetchHindsightGateway(HINDSIGHT_BASE_URL, HINDSIGHT_API_KEY),
    reviewQueue:
      options.reviewQueue ??
      new JsonlReviewQueue(registry.defaults.review_queue_path),
  });
}

function isAuthorized(req: IncomingMessage, routerToken?: string): boolean {
  const token = routerToken ?? ROUTER_TOKEN;
  if (!token) return true;
  return req.headers.authorization === `Bearer ${token}`;
}

async function readJson<T>(req: IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  for await (const chunk of req)
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? (JSON.parse(raw) as T) : ({} as T);
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function parseMemoryPath(
  pathname: string,
): { writerId: string; action: "retain" | "recall" } | null {
  const retain = pathname.match(/^\/v1\/default\/banks\/([^/]+)\/memories$/);
  if (retain)
    return { writerId: decodeURIComponent(retain[1]), action: "retain" };

  const recall = pathname.match(
    /^\/v1\/default\/banks\/([^/]+)\/memories\/recall$/,
  );
  if (recall)
    return { writerId: decodeURIComponent(recall[1]), action: "recall" };

  return null;
}

export function createMemoryRouterServer(
  options: CreateMemoryRouterServerOptions = {},
) {
  const policy = buildPolicy(options);

  return createServer(async (req, res) => {
    try {
      const method = req.method ?? "GET";
      const url = new URL(req.url ?? "/", "http://memory-router.local");

      if (method === "GET" && url.pathname === "/health") {
        return send(res, 200, { status: "healthy", service: "memory-router" });
      }

      if (!isAuthorized(req, options.routerToken))
        return send(res, 401, { error: "unauthorized" });

      if (method === "GET" && url.pathname === "/version") {
        return send(res, 200, {
          api_version: "0.8.3",
          router: "memory-router",
          features: { policy_facade: true },
        });
      }

      const memoryPath = parseMemoryPath(url.pathname);
      if (method === "POST" && memoryPath?.action === "retain") {
        const body = await readJson<RetainBody>(req);
        const result = await policy.retain(memoryPath.writerId, body);
        return send(res, 200, result);
      }

      if (method === "POST" && memoryPath?.action === "recall") {
        const body = await readJson<RecallBody>(req);
        const result = await policy.recall(memoryPath.writerId, body);
        return send(res, 200, result);
      }

      const denied = policy.denyEndpoint(method, url.pathname);
      return send(res, 404, denied);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return send(res, 500, { error: message });
    }
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  createMemoryRouterServer().listen(PORT, () => {
    console.log(`memory-router listening on ${PORT}`);
  });
}
