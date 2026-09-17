// Package-consumer check: packs the UI like the release pipeline does and
// asserts the published artifact is a self-contained static bundle a host can
// serve without the repository. Run after npm run build (prepack rebuilds).

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const work = mkdtempSync(path.join(ROOT, ".pack-test-"));

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) yield* walk(full);
    else yield full;
  }
}

try {
  const out = execFileSync("npm", ["pack", "--json", "--pack-destination", work], {
    cwd: ROOT,
    encoding: "utf8",
  });
  // prepack rebuilds and logs before npm prints the JSON result; take the tail.
  const [{ filename }] = JSON.parse(out.slice(out.lastIndexOf("\n[")));
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.equal(filename, `${pkg.name.replace(/^@/, "").replace("/", "-")}-${pkg.version}.tgz`);

  const extracted = path.join(work, "extracted");
  mkdirSync(extracted);
  execFileSync("tar", ["-xzf", path.join(work, filename), "-C", extracted]);
  rmSync(path.join(work, filename));
  const files = [...walk(extracted)].map((f) => path.relative(extracted, f));

  const packedManifest = JSON.parse(
    readFileSync(path.join(extracted, "package", "package.json"), "utf8"),
  );
  assert.equal(packedManifest.private, undefined, "published package must not stay private");
  assert.equal(packedManifest.version, pkg.version);
  assert.equal(packedManifest.license, "MIT");

  for (const required of [
    path.join("package", "dist", "index.html"),
    path.join("package", "README.md"),
    path.join("package", "LICENSE"),
  ]) {
    assert.ok(files.includes(required), `tarball is missing ${required}`);
  }
  assert.ok(
    files.some((f) => /^package[\\/]dist[\\/]assets[\\/].+\.js$/.test(f)),
    "tarball is missing bundled assets",
  );

  const indexHtml = readFileSync(path.join(extracted, "package", "dist", "index.html"), "utf8");
  assert.match(indexHtml, /<script/, "dist/index.html must reference the bundle");

  for (const file of files) {
    assert.ok(!/\.(ts|tsx|map)$/.test(file), `source or map leaked into tarball: ${file}`);
    assert.ok(!/(^|[\\/])(src|tests|node_modules)([\\/]|$)/.test(file), `workspace path leaked: ${file}`);
    assert.ok(!/\.(pem|key|p12|pfx)$/.test(file), `key material leaked into tarball: ${file}`);
  }

  console.log(`package-consumer ok: ${filename} (${files.length} files)`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
