import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import process from "node:process";

type Position = { line: number; column: number };
type Location = { start: Position; end: Position };
type FileCoverage = {
  path: string;
  statementMap: Record<string, Location>;
  s: Record<string, number>;
  branchMap: Record<string, { locations: Location[] }>;
  b: Record<string, number[]>;
};

type ChangedLines = Map<string, Set<number>>;

const base = process.argv[2] ?? "origin/main";
const lineThreshold = Number(process.argv[3] ?? "90");
const branchThreshold = Number(process.argv[4] ?? "85");
const coveragePath = resolve("coverage/coverage-final.json");

const coverage = JSON.parse(await readFile(coveragePath, "utf8")) as Record<
  string,
  FileCoverage
>;
const changedLines = readChangedLines(base);

let lineTotal = 0;
let lineCovered = 0;
let branchTotal = 0;
let branchCovered = 0;

for (const fileCoverage of Object.values(coverage)) {
  const file = normalizePath(relative(process.cwd(), fileCoverage.path));
  const changed = changedLines.get(file);
  if (!changed?.size) continue;

  const lineHits = new Map<number, number>();
  for (const [id, location] of Object.entries(fileCoverage.statementMap)) {
    const line = location.start.line;
    const hits = fileCoverage.s[id] ?? 0;
    lineHits.set(line, Math.max(lineHits.get(line) ?? 0, hits));
  }

  for (const line of changed) {
    const hits = lineHits.get(line);
    if (hits === undefined) continue;
    lineTotal += 1;
    if (hits > 0) lineCovered += 1;
  }

  for (const [id, branch] of Object.entries(fileCoverage.branchMap)) {
    const hits = fileCoverage.b[id] ?? [];
    branch.locations.forEach((location, index) => {
      if (!changed.has(location.start.line)) return;
      branchTotal += 1;
      if ((hits[index] ?? 0) > 0) branchCovered += 1;
    });
  }
}

const linePercent = percentage(lineCovered, lineTotal);
const branchPercent = percentage(branchCovered, branchTotal);

console.log(
  `Changed-code coverage: lines ${lineCovered}/${lineTotal} (${linePercent.toFixed(2)}%), branches ${branchCovered}/${branchTotal} (${branchPercent.toFixed(2)}%)`,
);

const failures: string[] = [];
if (lineTotal > 0 && linePercent < lineThreshold) {
  failures.push(`line coverage ${linePercent.toFixed(2)}% is below ${lineThreshold}%`);
}
if (branchTotal > 0 && branchPercent < branchThreshold) {
  failures.push(
    `branch coverage ${branchPercent.toFixed(2)}% is below ${branchThreshold}%`,
  );
}

if (failures.length) {
  throw new Error(`Changed-code coverage gate failed: ${failures.join("; ")}`);
}

function readChangedLines(compareBase: string): ChangedLines {
  const output = execFileSync(
    "git",
    ["diff", "--unified=0", "--no-color", `${compareBase}...HEAD`, "--", "src/**/*.ts"],
    { encoding: "utf8" },
  );
  const result: ChangedLines = new Map();
  let currentFile: string | undefined;

  for (const line of output.split("\n")) {
    if (line.startsWith("+++ b/")) {
      currentFile = normalizePath(line.slice(6));
      if (!result.has(currentFile)) result.set(currentFile, new Set());
      continue;
    }
    if (!currentFile || !line.startsWith("@@")) continue;

    const match = line.match(/\+(\d+)(?:,(\d+))?/);
    if (!match) continue;
    const start = Number(match[1]);
    const count = Number(match[2] ?? "1");
    const lines = result.get(currentFile)!;
    for (let offset = 0; offset < count; offset += 1) lines.add(start + offset);
  }

  return result;
}

function percentage(covered: number, total: number): number {
  return total === 0 ? 100 : (covered / total) * 100;
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/");
}
