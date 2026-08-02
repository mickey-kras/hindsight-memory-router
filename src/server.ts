import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { ParsedUrlQuery } from "node:querystring";
import { parse as parseUrl } from "node:url";
import {
  FetchHindsightGateway,
  type HindsightGateway,
} from "./hindsightClient.js";
import { HttpError, safeErrorBody } from "./httpError.js";
import { RouterPolicy } from "./policy.js";
import {
  QuarantineAdminService,
  type ApproveBody,
  type CleanupBody,
} from "./quarantine/quarantineAdmin.js";
import type { QuarantineRepository } from "./quarantine/repository.js";
import {
  createQuarantineRepository,
  DEFAULT_QUARANTINE_DATABASE_URL,
} from "./quarantine/repositoryFactory.js";
import {
  DEFAULT_QUARANTINE_LIMITS,
  EncryptedDatabaseQuarantineStore,
  type QuarantineStore,
  type QuarantineStoreLimits,
} from "./quarantine/quarantineStore.js";
import { loadRegistry } from "./registry.js";
import { parseRecallBody, parseRetainBody } from "./requestValidation.js";
import type { WriterRegistry } from "./types.js";

const PORT = Number(process.env.MEMORY_ROUTER_PORT ?? "8890");
const ROUTER_TOKEN = process.env.MEMORY_ROUTER_TOKEN;
const ADMIN_TOKEN = process.env.MEMORY_ROUTER_ADMIN_TOKEN;
const HINDSIGHT_BASE_URL =
  process.env.HINDSIGHT_BASE_URL ?? "http://hindsight:8888";
const HINDSIGHT_API_KEY = process.env.HINDSIGHT_API_KEY;
const REGISTRY_PATH = process.env.MEMORY_ROUTER_REGISTRY;
const QUARANTINE_PUBLIC_KEY = process.env.QUARANTINE_PUBLIC_KEY ?? "";
const QUARANTINE_DATABASE_URL =
  process.env.QUARANTINE_DATABASE_URL ?? DEFAULT_QUARANTINE_DATABASE_URL;
const QUARANTINE_MAX_POSTPONES = numberEnv("QUARANTINE_MAX_POSTPONES", 3);
const MAX_BODY_BYTES = Number(
  process.env.MEMORY_ROUTER_MAX_BODY_BYTES ?? "1048576",
);

export interface CreateMemoryRouterServerOptions {
  routerToken?: string;
  adminToken?: string;
  maxPostpones?: number;
  maxBodyBytes?: number;
  registry?: WriterRegistry;
  hindsight?: HindsightGateway;
  quarantineRepository?: QuarantineRepository;
  quarantineStore?: QuarantineStore;
  quarantinePublicKey?: string;
  quarantineLimits?: QuarantineStoreLimits;
  validateStorage?: boolean;
}

export interface ConfiguredMemoryRouterServer {
  server: Server;
  quarantineRepository: QuarantineRepository;
}

function buildHindsight(
  options: CreateMemoryRouterServerOptions,
): HindsightGateway {
  return (
    options.hindsight ??
    new FetchHindsightGateway(HINDSIGHT_BASE_URL, HINDSIGHT_API_KEY)
  );
}

function buildRegistry(
  options: CreateMemoryRouterServerOptions,
): WriterRegistry {
  return options.registry ?? loadRegistry(REGISTRY_PATH);
}

function buildLimits(): QuarantineStoreLimits {
  return {
    maxItemBytes: numberEnv(
      "QUARANTINE_MAX_ITEM_BYTES",
      DEFAULT_QUARANTINE_LIMITS.maxItemBytes,
    ),
    maxPendingItems: numberEnv(
      "QUARANTINE_MAX_PENDING_ITEMS",
      DEFAULT_QUARANTINE_LIMITS.maxPendingItems,
    ),
    maxEncryptedBytes: numberEnv(
      "QUARANTINE_MAX_ENCRYPTED_BYTES",
      DEFAULT_QUARANTINE_LIMITS.maxEncryptedBytes,
    ),
    rateLimitMax: numberEnv(
      "QUARANTINE_RATE_LIMIT_MAX",
      DEFAULT_QUARANTINE_LIMITS.rateLimitMax,
    ),
    rateLimitWindowMs: numberEnv(
      "QUARANTINE_RATE_LIMIT_WINDOW_MS",
      DEFAULT_QUARANTINE_LIMITS.rateLimitWindowMs,
    ),
  };
}

export function createMemoryRouterServer(
  options: CreateMemoryRouterServerOptions = {},
): Server {
  const maxBodyBytes = options.maxBodyBytes ?? MAX_BODY_BYTES;
  const registry = buildRegistry(options);
  const hindsight = buildHindsight(options);
  const quarantineRepository = requireQuarantineRepository(options);
  const quarantineStore =
    options.quarantineStore ??
    new EncryptedDatabaseQuarantineStore(
      options.quarantinePublicKey ?? QUARANTINE_PUBLIC_KEY,
      quarantineRepository,
      options.quarantineLimits ?? buildLimits(),
    );
  const policy = new RouterPolicy({
    registry,
    hindsight,
    quarantineStore,
    quarantineRepository,
  });
  const admin = new QuarantineAdminService({
    repository: quarantineRepository,
    hindsight,
    registry,
    maxPostpones: options.maxPostpones ?? QUARANTINE_MAX_POSTPONES,
  });

  return createServer(async (req, res) => {
    try {
      const method = req.method ?? "GET";
      const requestUrl = parseUrl(req.url ?? "/", true);
      const pathname = requestUrl.pathname ?? "/";

      if (method === "GET" && pathname === "/health") {
        return send(res, 200, { status: "healthy", service: "memory-router" });
      }

      if (pathname.startsWith("/admin/")) {
        if (!isAdminAuthorized(req, options.adminToken)) {
          return send(res, 401, { error: "unauthorized" });
        }
        if (method === "GET" && pathname === "/admin/quarantine/queue") {
          return send(
            res,
            200,
            await admin.listQueue(
              integerQuery(requestUrl.query, "limit", 100, 1, 500),
              integerQuery(
                requestUrl.query,
                "offset",
                0,
                0,
                Number.MAX_SAFE_INTEGER,
              ),
            ),
          );
        }
        if (method === "GET" && pathname === "/admin/quarantine/stats") {
          return send(res, 200, await admin.stats());
        }
        if (method === "POST" && pathname === "/admin/quarantine/cleanup") {
          const body = (await readJson(req, maxBodyBytes)) as CleanupBody;
          return send(res, 200, await admin.cleanup(body));
        }

        const itemPath = parseAdminItemPath(pathname);
        if (itemPath?.action === "read" && method === "GET") {
          return send(res, 200, await admin.readItem(itemPath.quarantineId));
        }
        if (itemPath?.action === "approve" && method === "POST") {
          const body = (await readJson(req, maxBodyBytes)) as ApproveBody;
          return send(
            res,
            200,
            await admin.approve(itemPath.quarantineId, body),
          );
        }
        if (itemPath?.action === "reject" && method === "POST") {
          return send(res, 200, await admin.reject(itemPath.quarantineId));
        }
        if (itemPath?.action === "postpone" && method === "POST") {
          return send(res, 200, await admin.postpone(itemPath.quarantineId));
        }
        return send(res, 404, { error: "admin_endpoint_not_found" });
      }

      if (!isAuthorized(req, options.routerToken)) {
        return send(res, 401, { error: "unauthorized" });
      }

      if (method === "GET" && pathname === "/version") {
        return send(res, 200, {
          api_version: "0.9.0",
          router: "memory-router",
          features: {
            policy_facade: true,
            encrypted_quarantine: true,
            quarantine_admin_api: true,
            quarantine_database: true,
          },
        });
      }

      const memoryPath = parseMemoryPath(pathname);
      if (method === "POST" && memoryPath?.action === "retain") {
        const body = parseRetainBody(await readJson(req, maxBodyBytes));
        const result = await policy.retain(memoryPath.writerId, body);
        return send(res, 200, result);
      }

      if (method === "POST" && memoryPath?.action === "recall") {
        const body = parseRecallBody(await readJson(req, maxBodyBytes));
        const result = await policy.recall(memoryPath.writerId, body);
        return send(res, 200, result);
      }

      const denied = await policy.denyEndpoint(method, pathname);
      return send(res, 404, denied);
    } catch (error) {
      const response = safeErrorBody(error);
      if (response.status === 500) {
        process.stderr.write("memory-router request failed\n");
      }
      return send(res, response.status, response.body);
    }
  });
}

export async function createConfiguredMemoryRouterServer(): Promise<ConfiguredMemoryRouterServer> {
  assertNoPrivateKeyEnvironment();
  const quarantineRepository = await createQuarantineRepository(
    QUARANTINE_DATABASE_URL,
  );
  const server = createMemoryRouterServer({
    quarantineRepository,
    quarantinePublicKey: QUARANTINE_PUBLIC_KEY,
  });
  return { server, quarantineRepository };
}

export function assertNoPrivateKeyEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): void {
  const injected = Object.keys(environment).find((name) =>
    name.startsWith("QUARANTINE_PRIVATE_KEY"),
  );
  if (injected) {
    throw new Error(
      `${injected} must not be available to the memory-router process`,
    );
  }
}

function requireQuarantineRepository(
  options: CreateMemoryRouterServerOptions,
): QuarantineRepository {
  if (!options.quarantineRepository) {
    throw new Error(
      "quarantineRepository is required; use createConfiguredMemoryRouterServer for environment-based configuration",
    );
  }
  return options.quarantineRepository;
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

async function readJson(
  req: IncomingMessage,
  maxBodyBytes: number,
): Promise<unknown> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.length;
    if (totalBytes > maxBodyBytes) {
      throw new HttpError(413, "payload_too_large", "payload too large");
    }
    chunks.push(buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return {};
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new HttpError(400, "invalid_json", "invalid JSON body");
  }
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function parseMemoryPath(
  pathname: string,
): { writerId: string; action: "retain" | "recall" } | null {
  const retain = pathname.match(/^\/v1\/default\/banks\/([^/]+)\/memories$/);
  if (retain) {
    return { writerId: decodeURIComponent(retain[1]), action: "retain" };
  }

  const recall = pathname.match(
    /^\/v1\/default\/banks\/([^/]+)\/memories\/recall$/,
  );
  if (recall) {
    return { writerId: decodeURIComponent(recall[1]), action: "recall" };
  }

  return null;
}

function parseAdminItemPath(pathname: string): {
  quarantineId: string;
  action: "read" | "approve" | "reject" | "postpone";
} | null {
  const match = pathname.match(
    /^\/admin\/quarantine\/items\/([^/]+)(?:\/(approve|reject|postpone))?$/,
  );
  if (!match) return null;
  return {
    quarantineId: decodeURIComponent(match[1]),
    action: (match[2] ?? "read") as "read" | "approve" | "reject" | "postpone",
  };
}

function integerQuery(
  query: ParsedUrlQuery,
  name: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = query[name];
  if (raw === undefined) return fallback;
  if (Array.isArray(raw)) {
    throw new HttpError(400, "invalid_query", `${name} is invalid`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new HttpError(400, "invalid_query", `${name} is invalid`);
  }
  return value;
}

function numberEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return value;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  createConfiguredMemoryRouterServer()
    .then(({ server, quarantineRepository }) => {
      server.listen(PORT, () => {
        process.stdout.write(`memory-router listening on ${PORT}\n`);
      });
      const shutdown = () => {
        server.close(() => {
          quarantineRepository.close().finally(() => process.exit(0));
        });
      };
      process.once("SIGINT", shutdown);
      process.once("SIGTERM", shutdown);
    })
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : "startup failed";
      process.stderr.write(`memory-router startup failed: ${message}\n`);
      process.exit(1);
    });
}
