import { HttpError } from "./httpError.js";
import { integerEnv } from "./integerEnv.js";
import { InMemorySlidingWindowRateLimiter } from "./quarantine/rateLimiter.js";

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
    readMax: integerEnv(
      environment,
      "MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX",
      DEFAULT_ADMIN_RATE_LIMIT.readMax,
      { minimum: 1 },
    ),
    writeMax: integerEnv(
      environment,
      "MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX",
      DEFAULT_ADMIN_RATE_LIMIT.writeMax,
      { minimum: 1 },
    ),
    windowMs: integerEnv(
      environment,
      "MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS",
      DEFAULT_ADMIN_RATE_LIMIT.windowMs,
      { minimum: 1 },
    ),
  };
}

export function classifyAdminRequest(method: string): AdminRequestClass {
  return method === "GET" || method === "HEAD" ? "read" : "write";
}

export class AdminRateLimiter {
  private readonly limiter = new InMemorySlidingWindowRateLimiter();

  constructor(
    private readonly config: AdminRateLimitConfig = DEFAULT_ADMIN_RATE_LIMIT,
    private readonly now: () => number = () => Date.now(),
  ) {}

  async consume(requestClass: AdminRequestClass): Promise<void> {
    const max =
      requestClass === "read" ? this.config.readMax : this.config.writeMax;
    try {
      await this.limiter.consume(
        `admin:${requestClass}`,
        { max, windowMs: this.config.windowMs },
        new Date(this.now()),
      );
    } catch (error) {
      if (error instanceof HttpError && error.status === 429) {
        throw new HttpError(
          429,
          "admin_rate_limited",
          `too many admin ${requestClass} requests`,
        );
      }
      throw error;
    }
  }
}
