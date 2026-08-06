import { describe, expect, it, vi } from "vitest";
import {
  assertDeploymentMode,
  deploymentModeConfigFromEnv,
} from "../src/deploymentMode.js";

describe("deployment modes", () => {
  it("defaults to single-process mode", () => {
    expect(deploymentModeConfigFromEnv({})).toEqual({
      mode: "single",
      databaseUrl: "sqlite:./data/quarantine.db",
      externalAdminRateLimit: false,
    });
    expect(() => assertDeploymentMode({})).not.toThrow();
  });

  it("rejects unknown deployment modes", () => {
    expect(() =>
      assertDeploymentMode({ MEMORY_ROUTER_DEPLOYMENT_MODE: "distributed" }),
    ).toThrow("must be either single or cluster");
  });

  it("requires PostgreSQL for cluster mode", () => {
    expect(() =>
      assertDeploymentMode({
        MEMORY_ROUTER_DEPLOYMENT_MODE: "cluster",
        QUARANTINE_DATABASE_URL: "sqlite:/state/quarantine.db",
        MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT: "true",
      }),
    ).toThrow("requires a PostgreSQL");
  });

  it("requires a shared external admin limiter for cluster mode", () => {
    expect(() =>
      assertDeploymentMode({
        MEMORY_ROUTER_DEPLOYMENT_MODE: "cluster",
        QUARANTINE_DATABASE_URL:
          "postgresql://router:secret@database:5432/quarantine",
      }),
    ).toThrow("requires MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT=true");
  });

  it("accepts cluster mode only with shared persistence and admin throttling", () => {
    expect(() =>
      assertDeploymentMode({
        MEMORY_ROUTER_DEPLOYMENT_MODE: "cluster",
        QUARANTINE_DATABASE_URL:
          "postgresql://router:secret@database:5432/quarantine",
        MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT: "true",
      }),
    ).not.toThrow();
  });

  it("warns when external admin limiting is declared in single mode", () => {
    const stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    try {
      assertDeploymentMode({
        MEMORY_ROUTER_DEPLOYMENT_MODE: "single",
        MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT: "true",
      });
      expect(stderr).toHaveBeenCalledWith(
        expect.stringContaining(
          "ensure the external limiter is actually present",
        ),
      );
    } finally {
      stderr.mockRestore();
    }
  });
});
