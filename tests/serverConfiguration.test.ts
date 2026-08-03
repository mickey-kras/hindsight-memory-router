import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { MemoryQuarantineRepository } from "../src/quarantine/memoryRepository.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import {
  assertRouterAuthEnvironment,
  createMemoryRouterServer,
} from "../src/server.js";

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

  it("stays quiet when both tokens are configured", () => {
    assertRouterAuthEnvironment({
      MEMORY_ROUTER_TOKEN: "router-token",
      MEMORY_ROUTER_ADMIN_TOKEN: "admin-token",
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
    expect(output).not.toContain("MEMORY_ROUTER_ADMIN_TOKEN is not set");
  });

  it("warns when the admin token is missing even if router auth is configured", () => {
    assertRouterAuthEnvironment({ MEMORY_ROUTER_TOKEN: "router-token" });
    const output = stderrOutput.join("");
    expect(output).toContain("MEMORY_ROUTER_ADMIN_TOKEN is not set");
    expect(output).not.toContain("MEMORY_ROUTER_TOKEN is not set");
  });

  it("warns loudly that anonymous access is development-only", () => {
    assertRouterAuthEnvironment({
      MEMORY_ROUTER_ALLOW_ANONYMOUS: "true",
      MEMORY_ROUTER_ADMIN_TOKEN: "admin-token",
    });
    const output = stderrOutput.join("");
    expect(output).toContain("MEMORY_ROUTER_ALLOW_ANONYMOUS=true");
    expect(output).toContain("Development only");
    expect(output).not.toContain("fail-closed");
  });
});
