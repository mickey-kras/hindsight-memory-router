import { describe, expect, it } from "vitest";
import { assertNoPrivateKeyEnvironment } from "../src/server.js";

describe("quarantine private-key isolation", () => {
  it("rejects private-key variables in the router environment", () => {
    expect(() =>
      assertNoPrivateKeyEnvironment({ QUARANTINE_PRIVATE_KEY: "secret" }),
    ).toThrow("must not be available to the memory-router process");
    expect(() =>
      assertNoPrivateKeyEnvironment({
        QUARANTINE_PRIVATE_KEY_FILE: "/run/secrets/quarantine-key",
      }),
    ).toThrow("QUARANTINE_PRIVATE_KEY_FILE");
  });

  it("allows the public-key-only router environment", () => {
    expect(() =>
      assertNoPrivateKeyEnvironment({
        QUARANTINE_PUBLIC_KEY: "public",
        MEMORY_ROUTER_TOKEN: "router-token",
      }),
    ).not.toThrow();
  });
});
