const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");

// Never follow candidate links or allow its tool-control files into a privileged
// scanner's configuration search. The original checkout remains available to
// scanners that accept an explicit trusted configuration.
function prepare(source, destination, trusted = path.resolve(__dirname, "../.."), security = false) {
  source = fs.realpathSync(source);
  destination = path.resolve(destination);
  assert.ok(!destination.startsWith(`${source}${path.sep}`));
  assert.ok(!fs.existsSync(destination), "Scan destination must be fresh");
  fs.mkdirSync(destination, { recursive: true });
  const controls = new Set([
    ".aislop",
    ".aislopignore",
    "biome.json",
    "biome.jsonc",
    ".git",
    "node_modules",
    // Pinned Aislop resolves Ruff from these project-local tool directories.
    ".venv",
    "venv",
    ".npmrc",
    ".semgrepignore",
    ".gitignore",
    ".gitleaks.toml",
    ".gitleaksignore",
    ".semgrep.yml",
    "pyproject.toml",
    "ruff.toml",
    ".ruff.toml",
    "setup.cfg",
    "tox.ini",
  ]);
  const directive = "aislop" + "-ignore";
  const suppression = new RegExp(`(?:\\/\\/|\\/\\*+|#|<!--|\\*)\\s*${directive}(?:-[A-Za-z][\\w-]*)?(?![\\w-])`);
  const duplicateSuppression = new RegExp(
    "aislop" + "[- ]ignore(?:-next-block|-file)?\\b.*\\b(?:duplicate-block|code-quality\\/duplicate-block)\\b",
  );
  function copy(from, to) {
    for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
      const input = path.join(from, entry.name);
      const output = path.join(to, entry.name);
      assert.ok(!entry.isSymbolicLink(), `Candidate symlink rejected: ${path.relative(source, input)}`);
      if ((security ? new Set([".git", "node_modules", ".venv", "venv"]).has(entry.name) : controls.has(entry.name)) || (!security && /^(?:eslint\.config\.|\.eslintrc|\.eslintignore$)/.test(entry.name))) continue;
      if (entry.isDirectory()) {
        fs.mkdirSync(output);
        copy(input, output);
      } else {
        assert.ok(entry.isFile(), "Candidate must contain only regular files and directories");
        // The pinned Aislop API always applies inline suppressions. Reject their
        // comment syntax and the duplicate detector's unanchored syntax before scanning.
        const content = fs.readFileSync(input, "utf8");
        assert.ok(
          security || (!suppression.test(content) && !duplicateSuppression.test(content)),
          `Candidate inline scanner suppression rejected: ${path.relative(source, input)}`,
        );
        if (!security && entry.name === "package.json") {
          const pkg = JSON.parse(fs.readFileSync(input, "utf8"));
          for (const key of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
            assert.ok(!Object.hasOwn(pkg[key] || {}, "knip"), "Candidate Knip execution is not permitted");
          }
        }
        fs.copyFileSync(input, output, fs.constants.COPYFILE_EXCL);
      }
    }
  }
  copy(source, destination);
  if (security) return destination;
  fs.cpSync(path.join(trusted, ".aislop"), path.join(destination, ".aislop"), { recursive: true });
  fs.copyFileSync(path.join(trusted, "pyproject.toml"), path.join(destination, "pyproject.toml"));
  fs.writeFileSync(path.join(destination, ".aislopignore"), "");
  return destination;
}
function prepareAudits(source, destination) {
  source = fs.realpathSync(source);
  assert.ok(!fs.existsSync(destination), "Audit destination must be fresh");
  for (const directory of [".", "ui", ".github/scripts"]) {
    const output = path.join(destination, directory);
    fs.mkdirSync(output, { recursive: true });
    for (const name of ["package.json", "package-lock.json"]) {
      const input = path.join(source, directory, name);
      assert.ok(fs.lstatSync(input).isFile() && fs.realpathSync(input) === input,
        "Audit inputs must be regular files without symlink parents");
      const content = JSON.parse(fs.readFileSync(input, "utf8"));
      fs.writeFileSync(path.join(output, name), JSON.stringify(content));
    }
  }
  const requirements = fs.readFileSync(path.join(source, "requirements.txt"), "utf8");
  // Accept only hash-locked PyPI requirements. No URLs, includes, indexes or editable packages.
  const logical = requirements.replace(/\\\r?\n/g, " ").split(/\r?\n/);
  for (const line of logical) {
    if (!line.trim() || line.trim().startsWith("#")) continue;
    assert.match(line.trim(), /^[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+(?:\s+--hash=sha256:[a-f0-9]{64})+$/,
      "Audit requirements must contain only pinned versions and SHA-256 hashes");
  }
  fs.writeFileSync(path.join(destination, "requirements.txt"), requirements);
}
module.exports = { prepare, prepareAudits };
if (require.main === module) {
  prepare(process.argv[2], process.argv[3]);
  if (process.argv[4]) prepareAudits(process.argv[2], process.argv[4]);
  if (process.argv[5]) prepare(process.argv[2], process.argv[5], undefined, true);
}
