import { afterEach, describe, expect, it, vi } from "vitest";
import { FetchHindsightGateway } from "../src/hindsightClient.js";
import { RouterPolicy } from "../src/policy.js";
import type { WriterRegistry } from "../src/types.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

const registry: WriterRegistry = {
  writers: {
    ops: {
      role: "ops",
      source: "test",
      write_bank: "ops",
      read_banks: ["ops"],
    },
  },
  defaults: {
    unknown_writer_action: "review_queue",
    suspicious_content_action: "review_queue",
  },
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Hindsight diagnostics", () => {
  it("logs one-line bounded metadata without upstream error text", async () => {
    const upstreamBody =
      "first line\r\nsecond line\u0000 Bearer secret https://user:pass@example.test/private";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(upstreamBody, { status: 503 })),
    );
    const stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    const quarantine = memoryQuarantine();
    const policy = new RouterPolicy({
      registry,
      hindsight: new FetchHindsightGateway("https://hindsight.test"),
      quarantineStore: quarantine.store,
      quarantineRepository: quarantine.repository,
    });

    await expect(policy.recall("ops", { query: "normal" })).resolves.toEqual({
      results: [],
    });

    expect(stderr).toHaveBeenCalledOnce();
    const log = String(stderr.mock.calls[0]?.[0]);
    expect(log).toContain('"event":"bank_unavailable"');
    expect(log).toContain('"error_kind":"http"');
    expect(log).toContain('"upstream_status":503');
    expect(log).toContain('"error_body_truncated":false');
    expect(log).not.toContain("first line");
    expect(log).not.toContain("Bearer secret");
    expect(log).not.toContain("user:pass");
    expect(log).not.toContain("\r");
    expect(log.match(/\n/g)).toHaveLength(1);
  });
});
