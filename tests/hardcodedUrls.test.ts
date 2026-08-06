import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Deterministic replacement for the ai-slop/hardcoded-url heuristic disabled
 * in .aislop/config.yml. Every HTTP(S) literal in src/ must be explicitly
 * allowlisted here with a justification.
 */
const ALLOWED_URL_LITERALS: ReadonlyArray<{ file: string; url: string }> = [
  {
    // Inert WHATWG parsing base for origin-form request targets. It is never
    // dereferenced; parseRequestUrl exposes only pathname and searchParams.
    file: "src/httpHelpers.ts",
    url: "https://memory-router.internal",
  },
  {
    // Documented default for HINDSIGHT_BASE_URL; real deployments override it
    // through environment configuration.
    file: "src/server.ts",
    url: "http://hindsight:8888",
  },
];

const URL_PATTERN = /https?:\/\/[^"'`\s\\]+/g;

function walkTypescriptFiles(directory: string, into: string[] = []): string[] {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      walkTypescriptFiles(path, into);
    } else if (entry.name.endsWith(".ts")) {
      into.push(path);
    }
  }
  return into;
}

describe("hardcoded URL allowlist", () => {
  it("permits only explicitly allowlisted URL literals in src/", () => {
    const found: Array<{ file: string; url: string }> = [];
    for (const file of walkTypescriptFiles("src")) {
      const content = readFileSync(file, "utf8");
      for (const match of content.matchAll(URL_PATTERN)) {
        found.push({ file: file.replaceAll("\\", "/"), url: match[0] });
      }
    }

    const unexpected = found.filter(
      (hit) =>
        !ALLOWED_URL_LITERALS.some(
          (allowed) => allowed.file === hit.file && allowed.url === hit.url,
        ),
    );
    expect(
      unexpected,
      "URL literal is not allowlisted. Move it to environment configuration " +
        "or add a justified exact entry to ALLOWED_URL_LITERALS.",
    ).toEqual([]);
  });

  it("keeps the allowlist free of stale entries", () => {
    const sources = walkTypescriptFiles("src").map((file) => ({
      file: file.replaceAll("\\", "/"),
      content: readFileSync(file, "utf8"),
    }));

    for (const allowed of ALLOWED_URL_LITERALS) {
      const source = sources.find((entry) => entry.file === allowed.file);
      expect(
        source?.content.includes(allowed.url),
        `stale allowlist entry: ${allowed.url} no longer appears in ${allowed.file}`,
      ).toBe(true);
    }
  });
});
