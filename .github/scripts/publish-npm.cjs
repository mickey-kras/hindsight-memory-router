const { execFileSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { setTimeout: sleep } = require("node:timers/promises");
const semver = require("semver");

const registry = "https://registry.npmjs.org";
const packageName = "@mickey-kras/memory-router-ui";

async function metadata(name, version) {
  const response = await fetch(`${registry}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`, {
    signal: AbortSignal.timeout(30_000),
    redirect: "error",
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`npm metadata request failed: HTTP ${response.status}`);
  return response.json();
}

function verifyPublished(pkg, published, integrity) {
  if (published.name !== pkg.name || published.version !== pkg.version || published.dist?.integrity !== integrity) {
    throw new Error(`npm integrity mismatch: ${pkg.name}@${pkg.version}`);
  }
  if (published.dist?.attestations?.provenance?.predicateType !== "https://slsa.dev/provenance/v1") {
    throw new Error(`npm provenance missing: ${pkg.name}@${pkg.version}`);
  }
}

async function publishPackage({
  pkg,
  digests,
  read = readFileSync,
  lookup = metadata,
  publish = (args) => execFileSync("npm", args, { stdio: "inherit", timeout: 120_000 }),
  wait = sleep,
}) {
  if (pkg.name !== packageName || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(pkg.version)) {
    throw new Error("Invalid UI package name or version");
  }
  const tarball = `mickey-kras-memory-router-ui-${pkg.version}.tgz`;
  const bytes = read(tarball);
  const checksum = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const recorded = digests.trim().split("\n").filter((line) => line.startsWith("ui-package="));
  if (recorded.length !== 1 || recorded[0] !== `ui-package=${checksum}`) {
    throw new Error("Release UI package checksum mismatch");
  }
  const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  const existing = await lookup(pkg.name, pkg.version);
  if (existing) {
    verifyPublished(pkg, existing, integrity);
    return;
  }
  const latest = await lookup(pkg.name, "latest");
  if (latest && !semver.valid(latest.version)) throw new Error("Invalid npm latest version");
  const tag = latest && semver.gt(latest.version, pkg.version) ? `release-${pkg.version}` : "latest";
  publish(["publish", resolve(tarball), "--registry", registry, "--access", "public",
    "--provenance", "--ignore-scripts", "--tag", tag]);
  for (let attempt = 0; attempt < 5; attempt++) {
    const published = await lookup(pkg.name, pkg.version);
    if (published) {
      verifyPublished(pkg, published, integrity);
      return;
    }
    if (attempt < 4) await wait(2000 * (attempt + 1));
  }
  throw new Error(`npm publication not visible: ${pkg.name}@${pkg.version}`);
}

if (require.main === module) {
  publishPackage({
    pkg: JSON.parse(readFileSync("ui/package.json", "utf8")),
    digests: readFileSync("image-digests.txt", "utf8"),
  }).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { publishPackage, metadata };
