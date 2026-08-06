import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  assertDeploymentMode,
  deploymentModeConfigFromEnv,
} from "../src/deploymentMode.js";

describe("deployment modes", () => {
  let stderr: ReturnType<typeof vi.spyOn>;
  let output: string[];

  beforeEach(() => {
    output = [];
    stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: unknown) => {
        output.push(String(chunk));
        return true;
      });
  });

  afterEach(() => stderr.mockRestore());

  it("parses single-process defaults", () => {
    expect(deploymentModeConfigFromEnv({})).toEqual({
      mode: "single",
      databaseUrl: "sqlite:./data/quarantine.db",
      externalAdminRateLimit: false,
    });
  });

  it("rejects unknown deployment modes with the received value", () => {
    expect(() =>
      assertDeploymentMode({ MEMORY_ROUTER_DEPLOYMENT_MODE: "distributed" }),
    ).toThrow('received "distributed"');
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

  it.each(["postgres://db/quarantine", "postgresql://db/quarantine"])(
    "accepts cluster mode with %s",
    (databaseUrl) => {
      expect(() =>
        assertDeploymentMode({
          MEMORY_ROUTER_DEPLOYMENT_MODE: "cluster",
          MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT: "true",
          QUARANTINE_DATABASE_URL: databaseUrl,
        }),
      ).not.toThrow();
    },
  );

  it("warns when external admin limiting is declared in single mode", () => {
    assertDeploymentMode({
      MEMORY_ROUTER_DEPLOYMENT_MODE: "single",
      MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT: "true",
    });
    expect(output.join("")).toContain(
      "ensure the external limiter is actually present",
    );
  });
});
