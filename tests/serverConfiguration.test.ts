import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { MemoryQuarantineRepository } from "../src/quarantine/memoryRepository.js";
import {
  createQuarantineRepository,
  validateQuarantineStorage,
} from "../src/quarantine/repositoryFactory.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import {
  assertRouterAuthEnvironment,
  createMemoryRouterServer,
} from "../src/server.js";
import { quarantineKeys } from "./quarantineTestUtils.js";

describe("memory-router server configuration", () => {
  it("requires an explicit quarantine repository", () => {
    expect(() =>
      createMemoryRouterServer({
        registry: DEFAULT_REGISTRY,
        hindsight: new FakeHindsightGateway(),
      }),
    ).toThrow("quarantineRepository is required");
  });

  it("validates the quarantine public key while constructing the server", () => {
    expect(() =>
      createMemoryRouterServer({
        registry: DEFAULT_REGISTRY,
        hindsight: new FakeHindsightGateway(),
        quarantineRepository: new MemoryQuarantineRepository(),
        quarantinePublicKey: "",
      }),
    ).toThrow("QUARANTINE_PUBLIC_KEY is required");
  });
});

describe("router authentication startup validation", () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;
  let stderrOutput: string[];

  beforeEach(() => {
    stderrOutput = [];
    stderrSpy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: unknown) => {
        stderrOutput.push(String(chunk));
        return true;
      });
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it("warns while the legacy migration superuser is configured", () => {
    assertRouterAuthEnvironment({
      MEMORY_ROUTER_TOKEN: "router-token",
      MEMORY_ROUTER_ADMIN_TOKEN: "admin-token",
    });
    const output = stderrOutput.join("");
    expect(output).toContain("legacy admin migration superuser is active");
    expect(output).not.toContain("fail-closed");
  });

  it("stays quiet when all scoped admin tokens are configured", () => {
    assertRouterAuthEnvironment({
      MEMORY_ROUTER_TOKEN: "router-token",
      MEMORY_ROUTER_ADMIN_READ_TOKEN: "read-token",
      MEMORY_ROUTER_ADMIN_REVIEW_TOKEN: "review-token",
      MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN: "cleanup-token",
    });
    expect(stderrOutput).toEqual([]);
  });

  it("warns that router authentication fails closed when unset", () => {
    assertRouterAuthEnvironment({
      MEMORY_ROUTER_ADMIN_TOKEN: "admin-token",
    });
    const output = stderrOutput.join("");
    expect(output).toContain("MEMORY_ROUTER_TOKEN is not set");
    expect(output).toContain("fail-closed");
    expect(output).toContain("legacy admin migration superuser is active");
    expect(output).not.toContain("admin read token is not set");
  });

  it("warns for every missing scoped admin capability", () => {
    assertRouterAuthEnvironment({ MEMORY_ROUTER_TOKEN: "router-token" });
    const output = stderrOutput.join("");
    expect(output).toContain("admin read token is not set");
    expect(output).toContain("admin review token is not set");
    expect(output).toContain("admin cleanup token is not set");
    expect(output).not.toContain("MEMORY_ROUTER_TOKEN is not set");
  });

  it("treats the review token as sufficient for admin reads", () => {
    assertRouterAuthEnvironment({
      MEMORY_ROUTER_TOKEN: "router-token",
      MEMORY_ROUTER_ADMIN_REVIEW_TOKEN: "review-token",
    });
    const output = stderrOutput.join("");
    expect(output).not.toContain("admin read token is not set");
    expect(output).not.toContain("admin review token is not set");
    expect(output).toContain("admin cleanup token is not set");
  });

  it("uses option overrides instead of contradictory environment values", () => {
    assertRouterAuthEnvironment(
      {
        MEMORY_ROUTER_TOKEN: "env-router-token",
        MEMORY_ROUTER_ADMIN_TOKEN: "env-legacy-token",
      },
      {
        router: "option-router-token",
        legacy: "",
        read: "option-read-token",
        review: "option-review-token",
        cleanup: "option-cleanup-token",
      },
    );
    expect(stderrOutput).toEqual([]);
  });

  it("warns when an empty option explicitly disables an environment token", () => {
    assertRouterAuthEnvironment(
      {
        MEMORY_ROUTER_TOKEN: "router-token",
        MEMORY_ROUTER_ADMIN_TOKEN: "env-legacy-token",
      },
      { legacy: "" },
    );
    const output = stderrOutput.join("");
    expect(output).toContain("admin read token is not set");
    expect(output).toContain("admin review token is not set");
    expect(output).toContain("admin cleanup token is not set");
    expect(output).not.toContain("legacy admin migration superuser is active");
  });

  it("warns loudly that anonymous access is development-only", () => {
    assertRouterAuthEnvironment({
      MEMORY_ROUTER_ALLOW_ANONYMOUS: "true",
      MEMORY_ROUTER_ADMIN_READ_TOKEN: "read-token",
      MEMORY_ROUTER_ADMIN_REVIEW_TOKEN: "review-token",
      MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN: "cleanup-token",
    });
    const output = stderrOutput.join("");
    expect(output).toContain("MEMORY_ROUTER_ALLOW_ANONYMOUS=true");
    expect(output).toContain("Development only");
    expect(output).not.toContain("fail-closed");
  });
});

const STORAGE_ENV_KEYS = [
  "MEMORY_ROUTER_TOKEN",
  "QUARANTINE_PUBLIC_KEY",
  "QUARANTINE_DATABASE_URL",
] as const;

describe("quarantine storage validation", () => {
  let directory: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "router-storage-"));
  });

  afterEach(() => {
    chmodSync(directory, 0o700);
    rmSync(directory, { recursive: true, force: true });
  });

  it("accepts a writable SQLite database", async () => {
    const repository = await createQuarantineRepository(
      `sqlite:${join(directory, "quarantine.db")}`,
    );
    try {
      await expect(
        validateQuarantineStorage(
          repository,
          `sqlite:${join(directory, "quarantine.db")}`,
        ),
      ).resolves.toBeUndefined();
    } finally {
      await repository.close();
    }
  });

  it("fails fast when the SQLite database file is not writable", async () => {
    const databaseUrl = `sqlite:${join(directory, "quarantine.db")}`;
    const repository = await createQuarantineRepository(databaseUrl);
    try {
      chmodSync(join(directory, "quarantine.db"), 0o444);
      await expect(
        validateQuarantineStorage(repository, databaseUrl),
      ).rejects.toThrow("not writable");
    } finally {
      chmodSync(join(directory, "quarantine.db"), 0o600);
      await repository.close();
    }
  });

  it("fails fast when the SQLite directory is not writable", async () => {
    const databaseUrl = `sqlite:${join(directory, "quarantine.db")}`;
    const repository = await createQuarantineRepository(databaseUrl);
    try {
      chmodSync(directory, 0o555);
      await expect(
        validateQuarantineStorage(repository, databaseUrl),
      ).rejects.toThrow("not writable");
    } finally {
      chmodSync(directory, 0o700);
      await repository.close();
    }
  });

  it("skips filesystem checks for in-memory and PostgreSQL storage", async () => {
    const repository = new MemoryQuarantineRepository();
    await expect(
      validateQuarantineStorage(repository, "sqlite::memory:"),
    ).resolves.toBeUndefined();
    await expect(
      validateQuarantineStorage(
        repository,
        "postgresql://user:password@database:5432/router",
      ),
    ).resolves.toBeUndefined();
  });

  it("fails fast when the repository is unreachable", async () => {
    const repository = new MemoryQuarantineRepository();
    vi.spyOn(repository, "ping").mockRejectedValue(
      new Error("connection refused"),
    );
    await expect(
      validateQuarantineStorage(repository, "sqlite::memory:"),
    ).rejects.toThrow("unreachable");
  });
});

describe("configured server storage validation", () => {
  let directory: string;
  let savedEnvironment: Array<[(typeof STORAGE_ENV_KEYS)[number], string?]>;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "router-configured-"));
    savedEnvironment = STORAGE_ENV_KEYS.map((key) => [key, process.env[key]]);
  });

  afterEach(() => {
    for (const [key, value] of savedEnvironment) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    chmodSync(directory, 0o700);
    rmSync(directory, { recursive: true, force: true });
  });

  function useStorageEnvironment(): string {
    process.env.MEMORY_ROUTER_TOKEN = "router-token";
    process.env.QUARANTINE_PUBLIC_KEY = quarantineKeys().publicKey;
    process.env.QUARANTINE_DATABASE_URL = `sqlite:${join(directory, "quarantine.db")}`;
    return process.env.QUARANTINE_DATABASE_URL;
  }

  it("validates storage by default during configured startup", async () => {
    useStorageEnvironment();
    vi.resetModules();
    const { createConfiguredMemoryRouterServer } =
      await import("../src/server.js");
    const configured = await createConfiguredMemoryRouterServer();
    await configured.quarantineRepository.ping();
    await configured.quarantineRepository.close();
    await new Promise<void>((resolve) => configured.server.close(resolve));
  });

  it("allows embedded deployments to opt out of storage validation", async () => {
    useStorageEnvironment();
    vi.resetModules();
    const { createConfiguredMemoryRouterServer } =
      await import("../src/server.js");
    const configured = await createConfiguredMemoryRouterServer({
      validateStorage: false,
    });
    await configured.quarantineRepository.close();
    await new Promise<void>((resolve) => configured.server.close(resolve));
  });

  it("fails configured startup when storage cannot be created", async () => {
    useStorageEnvironment();
    chmodSync(directory, 0o555);
    vi.resetModules();
    const { createConfiguredMemoryRouterServer } =
      await import("../src/server.js");
    await expect(createConfiguredMemoryRouterServer()).rejects.toThrow();
  });
});
