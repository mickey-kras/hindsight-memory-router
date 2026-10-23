const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { resolve } = require("node:path");
const { test } = require("node:test");
const { publishPackage, metadata } = require("./publish-npm.cjs");

function fixture() {
  const pkg = { name: "@mickey-kras/memory-router-ui", version: "0.2.0" };
  const bytes = Buffer.from("signed release tarball");
  const published = { ...pkg, dist: {
    integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
    attestations: { provenance: { predicateType: "https://slsa.dev/provenance/v1" } },
  } };
  const calls = [];
  let visible = false;
  return {
    published, calls,
    options: {
      pkg,
      digests: `ui-package=sha256:${createHash("sha256").update(bytes).digest("hex")}\n`,
      read: (path) => {
        assert.equal(path, "mickey-kras-memory-router-ui-0.2.0.tgz");
        return bytes;
      },
      lookup: async (_name, version) => version !== "latest" && visible ? published : null,
      publish: (args) => { calls.push(args); visible = true; },
      wait: async () => {},
    },
  };
}

test("publishes the signed tarball without repacking or lifecycle scripts", async () => {
  const { options, calls } = fixture();
  await publishPackage(options);
  assert.deepEqual(calls, [["publish", resolve("mickey-kras-memory-router-ui-0.2.0.tgz"),
    "--registry", "https://registry.npmjs.org", "--access", "public", "--provenance",
    "--ignore-scripts", "--tag", "latest"]]);
});

test("retry skips an identical version with provenance", async () => {
  const { options, published, calls } = fixture();
  options.lookup = async () => published;
  await publishPackage(options);
  assert.deepEqual(calls, []);
});

test("rejects changed bytes, duplicate checksums, and invalid package identity before lookup", async () => {
  for (const change of [
    (options) => { options.digests = "ui-package=sha256:wrong"; },
    (options) => { options.digests += options.digests; },
    (options) => { options.pkg.name = "@another/ui"; },
    (options) => { options.pkg.version = "../0.2.0"; },
  ]) {
    const { options, calls } = fixture();
    change(options);
    options.lookup = async () => assert.fail("must not access npm");
    await assert.rejects(publishPackage(options), /Invalid UI|checksum mismatch/);
    assert.deepEqual(calls, []);
  }
});

test("existing version must match identity, integrity and provenance", async () => {
  for (const change of [
    (published) => { published.name = "another"; },
    (published) => { published.version = "0.1.0"; },
    (published) => { published.dist.integrity = "sha512-other"; },
    (published) => { delete published.dist.attestations; },
  ]) {
    const { options, published, calls } = fixture();
    change(published);
    options.lookup = async () => published;
    await assert.rejects(publishPackage(options), /integrity mismatch|provenance missing/);
    assert.deepEqual(calls, []);
  }
});

test("older publication does not move latest backwards", async () => {
  const { options, calls } = fixture();
  const lookup = options.lookup;
  options.lookup = async (name, version) => version === "latest" ? { version: "1.0.0" } : lookup(name, version);
  await publishPackage(options);
  assert.equal(calls[0].at(-1), "release-0.2.0");
});

test("publication visibility is retried with a bounded wait", async () => {
  const { options, published, calls } = fixture();
  const waits = [];
  let lookups = 0;
  options.lookup = async (_name, version) => version === "latest" ? null : ++lookups === 12 ? published : null;
  options.wait = async (ms) => { waits.push(ms); };
  await publishPackage(options);
  assert.equal(waits.reduce((total, ms) => total + ms, 0), 300_000);
  assert.equal(calls.length, 1);
});

test("missing publication and failed npm command fail loudly", async () => {
  const { options, calls } = fixture();
  const waits = [];
  options.lookup = async () => null;
  options.wait = async (ms) => { waits.push(ms); };
  await assert.rejects(publishPackage(options), /publication not visible after 10 minutes/);
  assert.equal(waits.reduce((total, ms) => total + ms, 0), 600_000);
  assert.equal(calls.length, 1);
  options.publish = () => { throw new Error("npm failed"); };
  await assert.rejects(publishPackage(options), /npm failed/);
});

test("registry distinguishes absence from authentication, rate limits and server failures", async (t) => {
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(url, "https://registry.npmjs.org/%40mickey-kras%2Fmemory-router-ui/0.2.0");
    assert.equal(options.redirect, "error");
    return new Response(null, { status: 404 });
  });
  assert.equal(await metadata("@mickey-kras/memory-router-ui", "0.2.0"), null);
  for (const status of [401, 403, 429, 500]) {
    globalThis.fetch.mock.mockImplementation(async () => new Response(null, { status }));
    await assert.rejects(metadata("@mickey-kras/memory-router-ui", "0.2.0"), new RegExp(`HTTP ${status}`));
  }
});
