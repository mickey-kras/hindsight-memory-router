import { HttpError } from "./httpError.js";

export type AdminRequestClass = "read" | "write";

export interface AdminRateLimitConfig {
  readMax: number;
  writeMax: number;
  windowMs: number;
}

export const DEFAULT_ADMIN_RATE_LIMIT: AdminRateLimitConfig = {
  readMax: 120,
  writeMax: 30,
  windowMs: 60_000,
};

export function adminRateLimitConfigFromEnv(
  environment: NodeJS.ProcessEnv = process.env,
): AdminRateLimitConfig {
  return {
    readMax: numberEnv(
      environment,
      "MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX",
      DEFAULT_ADMIN_RATE_LIMIT.readMax,
    ),
    writeMax: numberEnv(
      environment,
      "MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX",
      DEFAULT_ADMIN_RATE_LIMIT.writeMax,
    ),
    windowMs: numberEnv(
      environment,
      "MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS",
      DEFAULT_ADMIN_RATE_LIMIT.windowMs,
    ),
  };
}

export function classifyAdminRequest(method: string): AdminRequestClass {
  return method === "GET" || method === "HEAD" ? "read" : "write";
}

// This protects one router process. Multi-instance deployments need a shared edge limit.
export class AdminRateLimiter {
  private readonly windows: Record<AdminRequestClass, number[]> = {
    read: [],
    write: [],
  };

  constructor(
    private readonly config: AdminRateLimitConfig = DEFAULT_ADMIN_RATE_LIMIT,
    private readonly now: () => number = () => Date.now(),
  ) {}

  consume(requestClass: AdminRequestClass): void {
    const max =
      requestClass === "read" ? this.config.readMax : this.config.writeMax;
    if (max <= 0 || this.config.windowMs <= 0) return;
    const now = this.now();
    const windowStart = now - this.config.windowMs;
    const hits = this.windows[requestClass].filter(
      (timestamp) => timestamp > windowStart,
    );
    if (hits.length >= max) {
      throw new HttpError(
        429,
        "admin_rate_limited",
        `too many admin ${requestClass} requests`,
      );
    }
    hits.push(now);
    this.windows[requestClass] = hits;
  }
}

function numberEnv(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
): number {
  const raw = environment[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return value;
}
