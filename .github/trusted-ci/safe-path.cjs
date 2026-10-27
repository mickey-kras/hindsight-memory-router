const { mkdirSync, symlinkSync, realpathSync, existsSync } = require("node:fs");
const { join } = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");
const assert = require("node:assert/strict");

function safePath(directory) {
  mkdirSync(directory, { recursive: true });
  const names = ["node", "npm", "git", "which"];
  if (spawnSync("/usr/bin/which", ["ruff"]).status === 0) names.push("ruff");
  for (const name of names) {
    const executable = realpathSync(execFileSync("/usr/bin/which", [name], { encoding: "utf8" }).trim());
    const link = join(directory, name);
    if (!existsSync(link)) symlinkSync(executable, link);
    assert.equal(realpathSync(link), executable, "Scanner tool path was replaced");
  }
  return directory;
}
module.exports = { safePath };
