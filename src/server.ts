import { createServer, type Server } from "node:http";
import { parse as parseUrl } from "node:url";
import {
  AdminRateLimiter,
  adminRateLimitConfigFromEnv,
  classifyAdminRequest,
} from "./adminRateLimit.js";
import {
  FetchHindsightGateway,
  type HindsightGateway,
} from "./hindsightClient.js";
import { safeErrorBody } from "./httpError.js";
import {
  integerQuery,
  parseAdminItemPath,
  parseMemoryPath,
  readJson,
  send,
} from "./httpHelpers.js";
import { RouterPolicy } from "./policy.js";
import {
  QuarantineAdminService,
  type ApproveBody,
  type CleanupBody,
} from "./quarantine/quarantineAdmin.js";
import {
  PostgresSlidingWindowRateLimiter,
  type QuarantineRateLimiter,
} from "./quarantine/rateLimiter.js";
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
import {
  assertNoPrivateKeyEnvironment,
  assertRouterAuthEnvironment,
  createAuthFailureAuditor,
  isAdminAuthorized,
  isAuthorized,
} from "./routerAuth.js";
import type { WriterRegistry } from "./types.js";

export { assertNoPrivateKeyEnvironment, assertRouterAuthEnvironment };

const PORT = Number(process.env.MEMORY_ROUTER_PORT ?? "8890");
const ALLOW_ANONYMOUS = process.env.MEMORY_ROUTER_ALLOW_ANONYMOUS === "true";
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
  allowAnonymous?: boolean;
  adminRateLimiter?: AdminRateLimiter;
  maxPostpones?: number;
  maxBodyBytes?: number;
  registry?: WriterRegistry;
  hindsight?: HindsightGateway;
  quarantineRepository?: QuarantineRepository;
  quarantineStore?: QuarantineStore;
  quarantinePublicKey?: string;
  quarantineLimits?: QuarantineStoreLimits;
  quarantineRateLimiter?: QuarantineRateLimiter;
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
    rateLimitGlobalMax: numberEnv(
      "QUARANTINE_RATE_LIMIT_GLOBAL_MAX",
      DEFAULT_QUARANTINE_LIMITS.rateLimitGlobalMax,
    ),
    requarantineOpsMax: numberEnv(
      "QUARANTINE_REQUARANTINE_OPS_MAX",
      DEFAULT_QUARANTINE_LIMITS.requarantineOpsMax,
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
      options.quarantineRateLimiter,
    );
  const allowAnonymous = options.allowAnonymous ?? ALLOW_ANONYMOUS;
  const adminRateLimiter =
    options.adminRateLimiter ??
    new AdminRateLimiter(adminRateLimitConfigFromEnv());
  const auditAuthFailure = createAuthFailureAuditor(quarantineStore);
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

      if (method === "GET" && pathname === "/ready") {
        try {
          await quarantineRepository.ping();
          return send(res, 200, { status: "ready", service: "memory-router" });
        } catch {
          return send(res, 503, {
            status: "not_ready",
            service: "memory-router",
          });
        }
      }

      if (pathname.startsWith("/admin/")) {
        if (!isAdminAuthorized(req, options.adminToken)) {
          await auditAuthFailure("admin");
          return send(res, 401, { error: "unauthorized" });
        }
        adminRateLimiter.consume(classifyAdminRequest(method));
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

      if (!isAuthorized(req, options.routerToken, allowAnonymous)) {
        await auditAuthFailure("router");
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
  assertRouterAuthEnvironment();
  const quarantineRepository = await createQuarantineRepository(
    QUARANTINE_DATABASE_URL,
  );
  const server = createMemoryRouterServer({
    quarantineRepository,
    quarantinePublicKey: QUARANTINE_PUBLIC_KEY,
  });
  return { server, quarantineRepository };
}

export async function createPostgresRateLimiter(
  connectionString: string,
): Promise<PostgresSlidingWindowRateLimiter> {
  const limiter = new PostgresSlidingWindowRateLimiter(connectionString);
  await limiter.initialize();
  return limiter;
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
