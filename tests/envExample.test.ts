import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Guards .env.example against drifting from the configuration the router
// actually reads. Every MEMORY_ROUTER_*/QUARANTINE_*/HINDSIGHT_* variable
// referenced by the server configuration must be present in .env.example.
const CONFIG_SOURCES = [
  "src/server.ts",
  "src/adminRateLimit.ts",
  "src/routerAuth.ts",
];

function envVarsReadByServer(): Set<string> {
  const names = new Set<string>();
  for (const source of CONFIG_SOURCES) {
    const text = readFileSync(source, "utf8");
    for (const match of text.matchAll(/process\.env\.([A-Z0-9_]+)/g)) {
      names.add(match[1]);
    }
    for (const match of text.matchAll(
      /"((?:MEMORY_ROUTER|QUARANTINE|HINDSIGHT)_[A-Z0-9_]+)"/g,
    )) {
      names.add(match[1]);
    }
  }
  return names;
}

function envExampleEntries(): Set<string> {
  const names = new Set<string>();
  for (const line of readFileSync(".env.example", "utf8").split("\n")) {
    const match = line.match(/^([A-Z0-9_]+)=/);
    if (match) names.add(match[1]);
  }
  return names;
}

describe(".env.example completeness", () => {
  it("documents every environment variable the server reads", () => {
    const documented = envExampleEntries();
    const missing: string[] = [];
    for (const name of envVarsReadByServer()) {
      // The private key must never be configured on the router process.
      if (name.startsWith("QUARANTINE_PRIVATE_KEY")) continue;
      if (!documented.has(name)) missing.push(name);
    }
    expect(missing).toEqual([]);
  });

  it("never suggests configuring the quarantine private key", () => {
    for (const name of envExampleEntries()) {
      expect(name.startsWith("QUARANTINE_PRIVATE_KEY")).toBe(false);
    }
  });
});
