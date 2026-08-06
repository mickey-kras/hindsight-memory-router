export type DeploymentMode = "single" | "cluster";

export interface DeploymentModeConfig {
  mode: DeploymentMode;
  databaseUrl: string;
  externalAdminRateLimit: boolean;
}

export function deploymentModeConfigFromEnv(
  environment: NodeJS.ProcessEnv = process.env,
): DeploymentModeConfig {
  const rawMode = environment.MEMORY_ROUTER_DEPLOYMENT_MODE ?? "single";
  if (rawMode !== "single" && rawMode !== "cluster") {
    throw new Error(
      "MEMORY_ROUTER_DEPLOYMENT_MODE must be either single or cluster",
    );
  }
  return {
    mode: rawMode,
    databaseUrl: environment.QUARANTINE_DATABASE_URL ?? "sqlite:./data/quarantine.db",
    externalAdminRateLimit:
      environment.MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT === "true",
  };
}

export function assertDeploymentMode(
  environment: NodeJS.ProcessEnv = process.env,
): void {
  const config = deploymentModeConfigFromEnv(environment);
  const postgres =
    config.databaseUrl.startsWith("postgres://") ||
    config.databaseUrl.startsWith("postgresql://");

  if (config.mode === "cluster") {
    if (!postgres) {
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
