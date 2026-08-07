import { createServer, type Server } from "node:http";
import {
  DEFAULT_HINDSIGHT_TIMEOUT_MS,
  FetchHindsightGateway,
  hindsightGatewayErrorDetails,
  HindsightGatewayError,
  type HindsightGateway,
} from "./hindsightClient.js";
import {
  AdminRateLimiter,
  adminRateLimitConfigFromEnv,
  classifyAdminRequest,
} from "./adminRateLimit.js";
import {
  HindsightLimits,
  hindsightLimitConfigFromEnv,
  type HindsightLimitConfig,
} from "./hindsightLimits.js";
import { safeErrorBody } from "./httpError.js";
import {
  integerQuery,
  parseAdminItemPath,
  parseMemoryPath,
  parseRequestUrl,
  readJson,
  send,
} from "./httpHelpers.js";
import { integerEnv } from "./integerEnv.js";
import { RouterPolicy } from "./policy.js";
import {
  QuarantineAdminService,
  type ApproveBody,
  type CleanupBody,
} from "./quarantine/quarantineAdmin.js";
import type { QuarantineRepository } from "./quarantine/repository.js";
import {
  PostgresSlidingWindowRateLimiter,
  type QuarantineRateLimiter,
  type RateLimitSession,
} from "./quarantine/rateLimiter.js";
import {
  createQuarantineRepository,
  DEFAULT_QUARANTINE_DATABASE_URL,
  isPostgresConnectionString,
  validateQuarantineStorage,
} from "./quarantine/repositoryFactory.js";
import { startQuarantineSweeper } from "./quarantine/sweeper.js";
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
  type AdminScope,
  type AdminTokens,
} from "./routerAuth.js";
import type { WriterRegistry } from "./types.js";

export { assertNoPrivateKeyEnvironment, assertRouterAuthEnvironment };

const PORT = integerEnv(process.env, "MEMORY_ROUTER_PORT", 8890, {
  minimum: 1,
});
const ALLOW_ANONYMOUS = process.env.MEMORY_ROUTER_ALLOW_ANONYMOUS === "true";
const HINDSIGHT_BASE_URL =
  process.env.HINDSIGHT_BASE_URL ?? "http://hindsight:8888";
const HINDSIGHT_API_KEY = process.env.HINDSIGHT_API_KEY;
const HINDSIGHT_TIMEOUT_MS = integerEnv(
  process.env,
  "HINDSIGHT_TIMEOUT_MS",
  DEFAULT_HINDSIGHT_TIMEOUT_MS,
  { minimum: 1 },
);
const REGISTRY_PATH = process.env.MEMORY_ROUTER_REGISTRY;
const QUARANTINE_PUBLIC_KEY = process.env.QUARANTINE_PUBLIC_KEY ?? "";
const QUARANTINE_DATABASE_URL =
  process.env.QUARANTINE_DATABASE_URL ?? DEFAULT_QUARANTINE_DATABASE_URL;
const QUARANTINE_MAX_POSTPONES = integerEnv(
  process.env,
  "QUARANTINE_MAX_POSTPONES",
  3,
);
const QUARANTINE_SWEEP_INTERVAL_SECONDS = integerEnv(
  process.env,
  "QUARANTINE_SWEEP_INTERVAL_SECONDS",
  3600,
);
const QUARANTINE_EVENT_RETENTION_DAYS = integerEnv(
  process.env,
  "QUARANTINE_EVENT_RETENTION_DAYS",
  90,
);
const MAX_BODY_BYTES = integerEnv(
  process.env,
  "MEMORY_ROUTER_MAX_BODY_BYTES",
  1048576,
  { minimum: 1 },
);

export interface CreateMemoryRouterServerOptions {
  routerToken?: string;
  adminToken?: string;
  adminReadToken?: string;
  adminReviewToken?: string;
  adminCleanupToken?: string;
  allowAnonymous?: boolean;
  adminRateLimiter?: AdminRateLimiter;
  maxPostpones?: number;
  maxBodyBytes?: number;
  registry?: WriterRegistry;
  hindsight?: HindsightGateway;
  hindsightLimits?: HindsightLimitConfig;
  hindsightRateLimiter?: RateLimitSession;
  quarantineRepository?: QuarantineRepository;
  quarantineStore?: QuarantineStore;
  quarantinePublicKey?: string;
  quarantineLimits?: QuarantineStoreLimits;
  quarantineRateLimiter?: QuarantineRateLimiter;
  sweepIntervalSeconds?: number;
  eventRetentionDays?: number;
}

export interface CreateConfiguredMemoryRouterServerOptions extends CreateMemoryRouterServerOptions {
  validateStorage?: boolean;
}

export interface ConfiguredMemoryRouterServer {
  server: Server;
  quarantineRepository: QuarantineRepository;
  quarantineRateLimiter?: PostgresSlidingWindowRateLimiter;
}

function buildHindsight(
  options: CreateMemoryRouterServerOptions,
): HindsightGateway {
  return (
    options.hindsight ??
    new FetchHindsightGateway(
      HINDSIGHT_BASE_URL,
      HINDSIGHT_API_KEY,
      HINDSIGHT_TIMEOUT_MS,
    )
  );
}

function buildRegistry(
  options: CreateMemoryRouterServerOptions,
): WriterRegistry {
  return options.registry ?? loadRegistry(REGISTRY_PATH);
}

function buildLimits(): QuarantineStoreLimits {
  return {
    maxItemBytes: integerEnv(
      process.env,
      "QUARANTINE_MAX_ITEM_BYTES",
      DEFAULT_QUARANTINE_LIMITS.maxItemBytes,
    ),
    maxPendingItems: integerEnv(
      process.env,
      "QUARANTINE_MAX_PENDING_ITEMS",
      DEFAULT_QUARANTINE_LIMITS.maxPendingItems,
    ),
    maxPendingItemsPerWriter: integerEnv(
      process.env,
      "QUARANTINE_MAX_PENDING_ITEMS_PER_WRITER",
      DEFAULT_QUARANTINE_LIMITS.maxPendingItemsPerWriter,
    ),
    maxEncryptedBytes: integerEnv(
      process.env,
      "QUARANTINE_MAX_ENCRYPTED_BYTES",
      DEFAULT_QUARANTINE_LIMITS.maxEncryptedBytes,
    ),
    rateLimitMax: integerEnv(
      process.env,
      "QUARANTINE_RATE_LIMIT_MAX",
      DEFAULT_QUARANTINE_LIMITS.rateLimitMax,
    ),
    rateLimitWindowMs: integerEnv(
      process.env,
      "QUARANTINE_RATE_LIMIT_WINDOW_MS",
      DEFAULT_QUARANTINE_LIMITS.rateLimitWindowMs,
    ),
    rateLimitGlobalMax: integerEnv(
      process.env,
      "QUARANTINE_RATE_LIMIT_GLOBAL_MAX",
      DEFAULT_QUARANTINE_LIMITS.rateLimitGlobalMax,
    ),
    distinctFamilyLimitMax: integerEnv(
      process.env,
      "QUARANTINE_DISTINCT_FAMILY_LIMIT_MAX",
      DEFAULT_QUARANTINE_LIMITS.distinctFamilyLimitMax,
    ),
    requarantineOpsMax: integerEnv(
      process.env,
      "QUARANTINE_REQUARANTINE_OPS_MAX",
      DEFAULT_QUARANTINE_LIMITS.requarantineOpsMax,
    ),
    itemTtlDays: integerEnv(process.env, "QUARANTINE_ITEM_TTL_DAYS", 30),
  };
}

export function createMemoryRouterServer(
  options: CreateMemoryRouterServerOptions = {},
): Server {
  const maxBodyBytes = options.maxBodyBytes ?? MAX_BODY_BYTES;
  const registry = buildRegistry(options);
  const hindsight = buildHindsight(options);
  const hindsightLimits = new HindsightLimits(
    options.hindsightLimits ?? hindsightLimitConfigFromEnv(),
    options.hindsightRateLimiter,
  );
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
  const adminTokens: AdminTokens = {
    legacy: options.adminToken,
    read: options.adminReadToken,
    review: options.adminReviewToken,
    cleanup: options.adminCleanupToken,
  };
  const adminRateLimiter =
    options.adminRateLimiter ??
    new AdminRateLimiter(adminRateLimitConfigFromEnv());
  const auditAuthFailure = createAuthFailureAuditor(quarantineStore);
  const policy = new RouterPolicy({
    registry,
    hindsight,
    hindsightLimits,
    quarantineStore,
    quarantineRepository,
  });
  const admin = new QuarantineAdminService({
    repository: quarantineRepository,
    hindsight,
    registry,
    maxPostpones: options.maxPostpones ?? QUARANTINE_MAX_POSTPONES,
  });
  const sweepIntervalSeconds =
    options.sweepIntervalSeconds ?? QUARANTINE_SWEEP_INTERVAL_SECONDS;
  const eventRetentionDays =
    options.eventRetentionDays ?? QUARANTINE_EVENT_RETENTION_DAYS;

  const server = createServer(async (req, res) => {
    try {
      const method = req.method ?? "GET";
      const requestUrl = parseRequestUrl(req.url ?? "/");
      const pathname = requestUrl.pathname;

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
        const adminScope = adminScopeForRequest(method, pathname);
        if (!isAdminAuthorized(req, adminScope, adminTokens)) {
          await auditAuthFailure("admin");
          return send(res, 401, { error: "unauthorized" });
        }
        await adminRateLimiter.consume(classifyAdminRequest(method));
        if (method === "GET" && pathname === "/admin/quarantine/queue") {
          return send(
            res,
            200,
            await admin.listQueue(
              integerQuery(requestUrl.searchParams, "limit", 100, 1, 500),
              integerQuery(
                requestUrl.searchParams,
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
        hindsightLimits.assertRetainBounds(body);
        const result = await policy.retain(memoryPath.writerId, body);
        return send(res, 200, result);
      }

      if (method === "POST" && memoryPath?.action === "recall") {
        const body = parseRecallBody(await readJson(req, maxBodyBytes));
        hindsightLimits.assertRecallBounds(body);
        const result = await policy.recall(memoryPath.writerId, body);
        return send(res, 200, result);
      }

      const denied = await policy.denyEndpoint(method, pathname);
      return send(res, 404, denied);
    } catch (error) {
      const response = safeErrorBody(error);
      if (error instanceof HindsightGatewayError) {
        process.stderr.write(
          `memory-router upstream request failed: ${JSON.stringify(hindsightGatewayErrorDetails(error))}\n`,
        );
      } else if (response.status === 500) {
        process.stderr.write("memory-router request failed\n");
      }
      return send(res, response.status, response.body, response.headers);
    }
  });

  if (sweepIntervalSeconds > 0) {
    const sweeper = startQuarantineSweeper(quarantineRepository, {
      intervalSeconds: sweepIntervalSeconds,
      eventRetentionDays,
    });
    server.once("close", () => clearInterval(sweeper));
  }
  return server;
}

export async function createConfiguredMemoryRouterServer(
  options: CreateConfiguredMemoryRouterServerOptions = {},
): Promise<ConfiguredMemoryRouterServer> {
  assertNoPrivateKeyEnvironment();
  assertRouterAuthEnvironment(process.env, {
    router: options.routerToken,
    legacy: options.adminToken,
    read: options.adminReadToken,
    review: options.adminReviewToken,
    cleanup: options.adminCleanupToken,
    allowAnonymous: options.allowAnonymous,
  });
  const hindsightLimits =
    options.hindsightLimits ?? hindsightLimitConfigFromEnv();
  const quarantineRepository = await createQuarantineRepository(
    QUARANTINE_DATABASE_URL,
  );
  if (options.validateStorage ?? true) {
    await validateQuarantineStorage(
      quarantineRepository,
      QUARANTINE_DATABASE_URL,
    );
  }
  const quarantineRateLimiter = await createSharedRateLimiter(
    QUARANTINE_DATABASE_URL,
  );
  const server = createMemoryRouterServer({
    ...options,
    hindsightLimits,
    hindsightRateLimiter: quarantineRateLimiter,
    quarantineRepository,
    quarantinePublicKey: options.quarantinePublicKey ?? QUARANTINE_PUBLIC_KEY,
    quarantineRateLimiter,
  });
  return { server, quarantineRepository, quarantineRateLimiter };
}

async function createSharedRateLimiter(
  connectionString: string,
): Promise<PostgresSlidingWindowRateLimiter | undefined> {
  if (!isPostgresConnectionString(connectionString)) {
    return undefined;
  }
  const limiter = new PostgresSlidingWindowRateLimiter(connectionString);
  await limiter.initialize();
  return limiter;
}

function adminScopeForRequest(method: string, pathname: string): AdminScope {
  if (method === "GET") return "read";
  if (method === "POST" && pathname === "/admin/quarantine/cleanup") {
    return "cleanup";
  }
  return "review";
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

if (import.meta.url === `file://${process.argv[1]}`) {
  createConfiguredMemoryRouterServer()
    .then(({ server, quarantineRepository, quarantineRateLimiter }) => {
      server.listen(PORT, () => {
        process.stdout.write(`memory-router listening on ${PORT}\n`);
      });
      const shutdown = () => {
        const forceCloseTimer = setTimeout(() => {
          server.closeAllConnections();
        }, 30_000);
        forceCloseTimer.unref();
        server.close(() => {
          clearTimeout(forceCloseTimer);
          const closeLimiter =
            quarantineRateLimiter?.close() ?? Promise.resolve();
          closeLimiter.finally(() => {
            quarantineRepository.close().finally(() => process.exit(0));
          });
        });
        server.closeIdleConnections();
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
