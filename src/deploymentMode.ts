import { booleanEnv } from "./booleanEnv.js";
import {
  DEFAULT_QUARANTINE_DATABASE_URL,
  isPostgresConnectionString,
} from "./quarantine/databaseUrl.js";

const DEPLOYMENT_MODE_ENV = "MEMORY_ROUTER_DEPLOYMENT_MODE";
const EXTERNAL_ADMIN_RATE_LIMIT_ENV = "MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT";
const QUARANTINE_DATABASE_URL_ENV = "QUARANTINE_DATABASE_URL";

export type DeploymentMode = "single" | "cluster";

export interface DeploymentModeConfig {
  mode: DeploymentMode;
  databaseUrl: string;
  externalAdminRateLimit: boolean;
}

export function deploymentModeConfigFromEnv(
  environment: NodeJS.ProcessEnv = process.env,
  databaseUrl = environment[QUARANTINE_DATABASE_URL_ENV] ??
    DEFAULT_QUARANTINE_DATABASE_URL,
): DeploymentModeConfig {
  const rawMode = environment[DEPLOYMENT_MODE_ENV] ?? "single";
  if (rawMode !== "single" && rawMode !== "cluster") {
    throw new Error(
      `${DEPLOYMENT_MODE_ENV} must be single or cluster; received ${JSON.stringify(rawMode)}`,
    );
  }
  return {
    mode: rawMode,
    databaseUrl,
    externalAdminRateLimit: booleanEnv(
      environment,
      EXTERNAL_ADMIN_RATE_LIMIT_ENV,
      false,
    ),
  };
}

export function assertDeploymentMode(
  environment: NodeJS.ProcessEnv = process.env,
  databaseUrl?: string,
): void {
  const config = deploymentModeConfigFromEnv(environment, databaseUrl);

  if (config.mode === "cluster") {
    if (!isPostgresConnectionString(config.databaseUrl)) {
      throw new Error(
        "cluster deployment mode requires a PostgreSQL QUARANTINE_DATABASE_URL",
      );
    }
    if (!config.externalAdminRateLimit) {
      throw new Error(
        "cluster deployment mode requires MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true because built-in admin throttling is process-local",
      );
    }
    return;
  }

  if (config.externalAdminRateLimit) {
    process.stderr.write(
      "memory-router WARNING: MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true in single mode; ensure the external limiter is actually present\n",
    );
  }
}
