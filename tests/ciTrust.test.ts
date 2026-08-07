import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const workflowsDir = join(root, ".github", "workflows");
const packageJson = JSON.parse(
  readFileSync(join(root, "package.json"), "utf8"),
) as {
  scripts?: Record<string, string>;
  devDependencies?: Record<string, string>;
  overrides?: Record<string, Record<string, string>>;
};

function workflow(name: string): string {
  return readFileSync(join(workflowsDir, name), "utf8");
}

describe("CI dependency trust", () => {
  it("runs an exact local Aislop dependency through npm scripts", () => {
    expect(packageJson.devDependencies?.aislop).toMatch(/^\d+\.\d+\.\d+$/u);
    expect(packageJson.scripts?.["aislop:ci:human"]).toBe("aislop ci --human");
    expect(packageJson.scripts?.["aislop:ci:sarif"]).toBe("aislop ci --sarif");
    expect(packageJson.scripts?.["aislop:fix:safe"]).toBe("aislop fix --safe");
    expect(packageJson.overrides?.aislop?.["adm-zip"]).toBe("0.6.0");

    for (const name of ["ci.yml", "aislop.yml"]) {
      const source = workflow(name);
      expect(source).toContain("npm ci");
      expect(source).toContain("npm run aislop:ci:human");
      expect(source).toContain("npm run --silent aislop:ci:sarif");
      expect(source).not.toContain("npx --yes aislop@latest");
    }
  });

  it("pins the Semgrep container by version and digest", () => {
    const source = workflow("ci.yml");
    const references = source.match(/semgrep\/semgrep:[^\s"']+/gu) ?? [];

    expect(references).not.toHaveLength(0);
    for (const reference of references) {
      expect(reference).toMatch(
        /^semgrep\/semgrep:\d+\.\d+\.\d+@sha256:[a-f0-9]{64}$/u,
      );
    }
    expect(source).not.toContain("semgrep/semgrep:latest");
  });

  it("does not execute mutable latest references in repository workflows", () => {
    for (const name of readdirSync(workflowsDir).filter((entry) =>
      entry.endsWith(".yml"),
    )) {
      const source = workflow(name);
      expect(source).not.toMatch(/\buses:\s+\S+@latest\b/u);
      expect(source).not.toMatch(/\bnpx\b[^\n]*@latest\b/u);
      expect(source).not.toMatch(/\bdocker\s+(?:pull|run)\b[^\n]*:latest\b/u);
    }
  });
});
