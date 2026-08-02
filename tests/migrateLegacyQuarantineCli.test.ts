import { describe, expect, it, vi } from "vitest";
import {
  parseArguments,
  runMigrateLegacyQuarantineCli,
} from "../src/cli/migrateLegacyQuarantine.js";

function capture() {
  let value = "";
  return {
    stream: { write: (chunk: string) => (value += chunk) },
    value: () => value,
  };
}

describe("legacy quarantine migration CLI", () => {
  it("parses explicit and environment database settings", () => {
    expect(
      parseArguments(
        [
          "--queue",
          "review.jsonl",
          "--objects",
          "objects",
          "--database",
          "sqlite:explicit.db",
        ],
        { QUARANTINE_DATABASE_URL: "sqlite:environment.db" },
      ),
    ).toEqual({
      queuePath: "review.jsonl",
      objectDirectory: "objects",
      databaseUrl: "sqlite:explicit.db",
    });
    expect(
      parseArguments(["--queue", "q", "--objects", "o"], {
        QUARANTINE_DATABASE_URL: "postgresql://database/quarantine",
      }).databaseUrl,
    ).toBe("postgresql://database/quarantine");
  });

  it("runs migration and writes its summary", async () => {
    const stdout = capture();
    const stderr = capture();
    const migrate = vi.fn(async () => ({
      imported: 2,
      skipped_existing: 1,
      skipped_finalized: 3,
      skipped_without_payload: 4,
    }));

    await expect(
      runMigrateLegacyQuarantineCli(
        ["--queue", "review.jsonl", "--objects", "objects"],
        {
          environment: { QUARANTINE_DATABASE_URL: "sqlite:quarantine.db" },
          readPrivateKey: async () => "  private key  ",
          migrate,
          stdout: stdout.stream,
          stderr: stderr.stream,
        },
      ),
    ).resolves.toBe(0);
    expect(migrate).toHaveBeenCalledWith({
      queuePath: "review.jsonl",
      objectDirectory: "objects",
      databaseUrl: "sqlite:quarantine.db",
      privateKey: "private key",
    });
    expect(JSON.parse(stdout.value())).toEqual({
      imported: 2,
      skipped_existing: 1,
      skipped_finalized: 3,
      skipped_without_payload: 4,
    });
    expect(stderr.value()).toBe("");
  });

  it("reports usage, empty-key, and migration errors", async () => {
    const usageError = capture();
    await expect(
      runMigrateLegacyQuarantineCli(["--unknown", "value"], {
        stderr: usageError.stream,
      }),
    ).resolves.toBe(1);
    expect(usageError.value()).toContain("usage:");

    const keyError = capture();
    await expect(
      runMigrateLegacyQuarantineCli(
        ["--queue", "q", "--objects", "o"],
        {
          readPrivateKey: async () => "   ",
          stderr: keyError.stream,
        },
      ),
    ).resolves.toBe(1);
    expect(keyError.value()).toContain("private key is required on stdin");

    const migrationError = capture();
    await expect(
      runMigrateLegacyQuarantineCli(
        ["--queue", "q", "--objects", "o"],
        {
          readPrivateKey: async () => "private-key",
          migrate: async () => {
            throw new Error("database unavailable");
          },
          stderr: migrationError.stream,
        },
      ),
    ).resolves.toBe(1);
    expect(migrationError.value()).toContain("database unavailable");
  });
});
