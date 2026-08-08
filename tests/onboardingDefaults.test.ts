import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_ADMIN_RATE_LIMIT,
  adminRateLimitConfigFromEnv,
} from "../src/adminRateLimit.js";
import { bootstrapQuarantineKeys } from "../src/cli/bootstrapQuarantineKeys.js";
import { deploymentModeConfigFromEnv } from "../src/deploymentMode.js";
import {
  DEFAULT_HINDSIGHT_LIMITS,
  hindsightLimitConfigFromEnv,
} from "../src/hindsightLimits.js";
import { DEFAULT_QUARANTINE_DATABASE_URL } from "../src/quarantine/databaseUrl.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { assertRouterAuthEnvironment } from "../src/routerAuth.js";

describe("onboarding defaults", () => {
  it("uses authoritative built-in tuning defaults when env is absent", () => {
    expect(adminRateLimitConfigFromEnv({})).toEqual(DEFAULT_ADMIN_RATE_LIMIT);
    expect(hindsightLimitConfigFromEnv({})).toEqual(DEFAULT_HINDSIGHT_LIMITS);
    expect(deploymentModeConfigFromEnv({})).toEqual({
      mode: "single",
      databaseUrl: DEFAULT_QUARANTINE_DATABASE_URL,
      externalAdminRateLimit: false,
    });
  });

  it("defaults quarantine storage to embedded SQLite", () => {
    expect(DEFAULT_QUARANTINE_DATABASE_URL).toBe("sqlite:./data/quarantine.db");
  });

  it.each([
    "sqlite:/var/lib/memory-router/quarantine.db",
    "postgresql://router:secret@database:5432/quarantine",
  ])("honors an explicit database URL override: %s", (databaseUrl) => {
    expect(
      deploymentModeConfigFromEnv({ QUARANTINE_DATABASE_URL: databaseUrl })
        .databaseUrl,
    ).toBe(databaseUrl);
  });

  it("uses a framework-neutral built-in registry", () => {
    expect(DEFAULT_REGISTRY.writers).toEqual({
      main: {
        role: "default",
        source: "application",
        write_bank: "main",
        read_banks: ["main"],
      },
    });
  });

  it("rejects invalid explicitly supplied boolean configuration", () => {
    expect(() =>
      deploymentModeConfigFromEnv({
        MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT: "yes",
      }),
    ).toThrow("MEMORY_ROUTER_EXTERNAL_ADMIN_RATE_LIMIT must be true or false");
    expect(() =>
      assertRouterAuthEnvironment({ MEMORY_ROUTER_ALLOW_ANONYMOUS: "yes" }),
    ).toThrow("MEMORY_ROUTER_ALLOW_ANONYMOUS must be true or false");
  });

  it("makes Docker data persistent/writable and keeps the private key out of the router", async () => {
    const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
    const compose = await readFile(new URL("../compose.yaml", import.meta.url), "utf8");
    const routerStart = compose.indexOf("\n  memory-router:\n");
    const volumesStart = compose.indexOf("\nvolumes:\n");
    expect(routerStart).toBeGreaterThan(0);
    expect(volumesStart).toBeGreaterThan(routerStart);
    const routerService = compose.slice(routerStart, volumesStart);

    expect(dockerfile).toContain("mkdir -p /app/data");
    expect(dockerfile).toContain("chown -R node:node /app/data /app/bootstrap");
    expect(dockerfile).toContain("USER node");
    expect(routerService).toContain("memory-router-data:/app/data");
    expect(routerService).toContain("memory-router-public-key:/app/bootstrap/public:ro");
    expect(routerService).not.toContain("memory-router-private-key");
  });

  it("bootstraps quarantine keys idempotently with restrictive private-key permissions", async () => {
    const directory = await mkdtemp(join(tmpdir(), "memory-router-keys-"));
    const publicKeyPath = join(directory, "public", "quarantine-public.pem");
    const privateKeyPath = join(directory, "private", "quarantine-private.pem");
    try {
      expect(
        await bootstrapQuarantineKeys({
          publicKeyPath,
          privateKeyPath,
          modulusLength: 2048,
        }),
      ).toBe("created");
      const firstPublicKey = await readFile(publicKeyPath, "utf8");
      const firstPrivateKey = await readFile(privateKeyPath, "utf8");
      expect(firstPublicKey).toContain("BEGIN PUBLIC KEY");
      expect(firstPrivateKey).toContain("BEGIN PRIVATE KEY");
      expect((await stat(privateKeyPath)).mode & 0o777).toBe(0o600);

      expect(
        await bootstrapQuarantineKeys({
          publicKeyPath,
          privateKeyPath,
          modulusLength: 2048,
        }),
      ).toBe("existing");
      expect(await readFile(publicKeyPath, "utf8")).toBe(firstPublicKey);
      expect(await readFile(privateKeyPath, "utf8")).toBe(firstPrivateKey);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
