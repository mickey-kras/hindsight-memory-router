import { mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { dirname, join } from "node:path";
import { URL } from "node:url";
import {
  FetchHindsightGateway,
  type HindsightGateway,
} from "./hindsightClient.js";
import { RouterPolicy } from "./policy.js";
import { QuarantineAdminService, type PromoteBody } from "./quarantineAdmin.js";
import {
  EncryptedFileQuarantineStore,
  type QuarantineStore,
} from "./quarantineStore.js";
import { loadRegistry } from "./registry.js";
import { JsonlReviewQueue, type ReviewQueue } from "./reviewQueue.js";
import type { RecallBody, RetainBody, WriterRegistry } from "./types.js";

const PORT = Number(process.env.MEMORY_ROUTER_PORT ?? "8890");
const ROUTER_TOKEN = process.env.MEMORY_ROUTER_TOKEN;
const ADMIN_TOKEN = process.env.MEMORY_ROUTER_ADMIN_TOKEN;
const HINDSIGHT_BASE_URL =
  process.env.HINDSIGHT_BASE_URL ?? "http://hindsight:8888";
const HINDSIGHT_API_KEY = process.env.HINDSIGHT_API_KEY;
const REGISTRY_PATH = process.env.MEMORY_ROUTER_REGISTRY;
const QUARANTINE_PUBLIC_KEY = process.env.QUARANTINE_PUBLIC_KEY;
const QUARANTINE_PRIVATE_KEY = process.env.QUARANTINE_PRIVATE_KEY;
const QUARANTINE_OBJECT_DIR =
  process.env.QUARANTINE_OBJECT_DIR ??
  "/volume1/reports/hindsight-quarantine/objects";
const QUARANTINE_MAX_POSTPONES = Number(
  process.env.QUARANTINE_MAX_POSTPONES ?? "3",
);

export interface CreateMemoryRouterServerOptions {
  routerToken?: string;
  adminToken?: string;
  quarantinePrivateKey?: string;
  quarantineObjectDir?: string;
  reviewQueuePath?: string;
  maxPostpones?: number;
  validateStorage?: boolean;
  registry?: WriterRegistry;
  hindsight?: HindsightGateway;
  reviewQueue?: ReviewQueue;
  quarantineStore?: QuarantineStore;
}

function buildHindsight(
  options: CreateMemoryRouterServerOptions,
): HindsightGateway {
  return (
    options.hindsight ??
    new FetchHindsightGateway(HINDSIGHT_BASE_URL, HINDSIGHT_API_KEY)
  );
}

function buildPolicy(
  options: CreateMemoryRouterServerOptions = {},
): RouterPolicy {
  const registry = options.registry ?? loadRegistry(REGISTRY_PATH);
  const reviewQueue =
    options.reviewQueue ??
    new JsonlReviewQueue(
      options.reviewQueuePath ?? registry.defaults.review_queue_path,
    );
  return new RouterPolicy({
    registry,
    hindsight: buildHindsight(options),
    reviewQueue,
    quarantineStore:
      options.quarantineStore ??
      new EncryptedFileQuarantineStore(
        QUARANTINE_PUBLIC_KEY,
        options.quarantineObjectDir ?? QUARANTINE_OBJECT_DIR,
      ),
  });
}

function buildAdmin(
  options: CreateMemoryRouterServerOptions = {},
): QuarantineAdminService | null {
  const registry = options.registry ?? loadRegistry(REGISTRY_PATH);
  const reviewQueuePath =
    options.reviewQueuePath ?? registry.defaults.review_queue_path;
  return new QuarantineAdminService({
    reviewQueuePath,
    quarantineObjectDir: options.quarantineObjectDir ?? QUARANTINE_OBJECT_DIR,
    quarantinePrivateKey:
      options.quarantinePrivateKey ?? QUARANTINE_PRIVATE_KEY,
    hindsight: buildHindsight(options),
    maxPostpones: options.maxPostpones ?? QUARANTINE_MAX_POSTPONES,
  });
}

function assertWritableDirectory(label: string, directory: string): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const probePath = join(
    directory,
    `.memory-router-write-test-${process.pid}-${Date.now()}`,
  );
  try {
    writeFileSync(probePath, "ok\n", { encoding: "utf8", mode: 0o600 });
    unlinkSync(probePath);
  } catch {
    throw new Error(`${label} is not writable: ${directory}`);
  }
}

function validateWritableStorage(
  options: CreateMemoryRouterServerOptions = {},
): void {
  const registry = options.registry ?? loadRegistry(REGISTRY_PATH);
  const reviewQueuePath =
    options.reviewQueuePath ?? registry.defaults.review_queue_path;
  const quarantineObjectDir =
    options.quarantineObjectDir ?? QUARANTINE_OBJECT_DIR;

  if (!options.reviewQueue) {
    assertWritableDirectory("review queue directory", dirname(reviewQueuePath));
  }

  if (!options.quarantineStore || options.adminToken || ADMIN_TOKEN) {
    assertWritableDirectory("quarantine object directory", quarantineObjectDir);
  }
}

function isAuthorized(req: IncomingMessage, routerToken?: string): boolean {
  const token = routerToken ?? ROUTER_TOKEN;
  if (!token) return true;
  return req.headers.authorization === `Bearer ${token}`;
}

function isAdminAuthorized(req: IncomingMessage, adminToken?: string): boolean {
  const token = adminToken ?? ADMIN_TOKEN;
  if (!token) return false;
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

function parseAdminItemPath(pathname: string): {
  quarantineId: string;
  action: "read" | "reject" | "postpone" | "promote";
} | null {
  const match = pathname.match(
    /^\/admin\/quarantine\/items\/([^/]+)(?:\/(reject|postpone|promote))?$/,
  );
  if (!match) return null;
  return {
    quarantineId: decodeURIComponent(match[1]),
    action: (match[2] ?? "read") as "read" | "reject" | "postpone" | "promote",
  };
}

export function createMemoryRouterServer(
  options: CreateMemoryRouterServerOptions = {},
) {
  if (options.validateStorage) validateWritableStorage(options);

  const policy = buildPolicy(options);
  const admin = buildAdmin(options);

  return createServer(async (req, res) => {
    try {
      const method = req.method ?? "GET";
      const url = new URL(req.url ?? "/", "http://memory-router.local");

      if (method === "GET" && url.pathname === "/health") {
        return send(res, 200, { status: "healthy", service: "memory-router" });
      }

      if (url.pathname.startsWith("/admin/")) {
        if (!admin || !isAdminAuthorized(req, options.adminToken)) {
          return send(res, 401, { error: "unauthorized" });
        }
        if (method === "GET" && url.pathname === "/admin/quarantine/queue") {
          return send(res, 200, admin.listQueue());
        }
        const itemPath = parseAdminItemPath(url.pathname);
        if (itemPath?.action === "read" && method === "GET") {
          return send(res, 200, admin.readItem(itemPath.quarantineId));
        }
        if (itemPath?.action === "reject" && method === "POST") {
          return send(res, 200, admin.reject(itemPath.quarantineId));
        }
        if (itemPath?.action === "postpone" && method === "POST") {
          return send(res, 200, admin.postpone(itemPath.quarantineId));
        }
        if (itemPath?.action === "promote" && method === "POST") {
          const body = await readJson<PromoteBody>(req);
          return send(
            res,
            200,
            await admin.promote(itemPath.quarantineId, body),
          );
        }
        return send(res, 404, { error: "admin endpoint not found" });
      }

      if (!isAuthorized(req, options.routerToken))
        return send(res, 401, { error: "unauthorized" });

      if (method === "GET" && url.pathname === "/version") {
        return send(res, 200, {
          api_version: "0.8.3",
          router: "memory-router",
          features: {
            policy_facade: true,
            encrypted_quarantine: true,
            quarantine_admin_api: true,
          },
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
    } catch {
      console.error("memory-router request failed");
      return send(res, 500, { error: "internal error" });
    }
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    createMemoryRouterServer({ validateStorage: true }).listen(PORT, () => {
      process.stdout.write(`memory-router listening on ${PORT}\n`);
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "startup failed";
    console.error(`memory-router startup failed: ${message}`);
    process.exit(1);
  }
}
