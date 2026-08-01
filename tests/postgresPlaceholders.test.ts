import { describe, expect, it } from "vitest";
import { toPostgresPlaceholders } from "../src/quarantine/postgresRepository.js";

describe("PostgreSQL placeholder translation", () => {
  it("rewrites parameter markers in order", () => {
    expect(
      toPostgresPlaceholders(
        "SELECT * FROM quarantine_items WHERE reason = ? AND status = ?",
        2,
      ),
    ).toBe(
      "SELECT * FROM quarantine_items WHERE reason = $1 AND status = $2",
    );
  });

  it("preserves question marks in quoted values and comments", () => {
    const statement = [
      "SELECT '?', \"?\", $$?$$, $tag$?$tag$",
      "-- ?",
      "/* ? */ WHERE quarantine_id = ?",
    ].join("\n");

    expect(toPostgresPlaceholders(statement, 1)).toBe(
      statement.replace("quarantine_id = ?", "quarantine_id = $1"),
    );
  });

  it("rejects ambiguous operators or incorrect parameter counts", () => {
    expect(() =>
      toPostgresPlaceholders("SELECT encrypted_envelope::jsonb ? 'payload'", 0),
    ).toThrow("placeholder count 1 does not match parameter count 0");
    expect(() =>
      toPostgresPlaceholders("SELECT * FROM quarantine_items WHERE reason = ?", 0),
    ).toThrow("placeholder count 1 does not match parameter count 0");
  });

  it("rejects unterminated SQL literals", () => {
    expect(() => toPostgresPlaceholders("SELECT '?' || '", 0)).toThrow(
      "unterminated SQL quoted value",
    );
    expect(() => toPostgresPlaceholders("SELECT /* ?", 0)).toThrow(
      "unterminated SQL block comment",
    );
  });
});
