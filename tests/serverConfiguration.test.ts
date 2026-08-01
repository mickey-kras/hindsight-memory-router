import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { MemoryQuarantineRepository } from "../src/quarantine/memoryRepository.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { createMemoryRouterServer } from "../src/server.js";

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
