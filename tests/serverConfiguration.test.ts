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

  it("stays quiet when a router token is configured", () => {
    assertRouterAuthEnvironment({ MEMORY_ROUTER_TOKEN: "router-token" });
    expect(stderrOutput).toEqual([]);
  });

  it("warns that authentication fails closed when no token is configured", () => {
    assertRouterAuthEnvironment({
      MEMORY_ROUTER_ADMIN_TOKEN: "admin-token",
    });
    expect(stderrOutput.join("")).toContain("MEMORY_ROUTER_TOKEN is not set");
    expect(stderrOutput.join("")).toContain("fail-closed");
    expect(stderrOutput.join("")).not.toContain(
      "MEMORY_ROUTER_ADMIN_TOKEN is not set",
    );
  });

  it("also warns when the admin token is missing", () => {
    assertRouterAuthEnvironment({});
    expect(stderrOutput.join("")).toContain(
      "MEMORY_ROUTER_ADMIN_TOKEN is not set",
    );
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
