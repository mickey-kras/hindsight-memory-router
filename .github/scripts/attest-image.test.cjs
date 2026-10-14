const test = require("node:test");
const assert = require("node:assert/strict");
const { mkdtempSync, writeFileSync, readFileSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const { attestImage, validateStatement, execute, SBOM_TYPE } = require("./attest-image.cjs");
const { PREDICATE_TYPE } = require("./provenance.cjs");

const context = { repo: { owner: "example", repo: "router" }, ref: "refs/heads/main", sha: "a".repeat(40) };
const digest = `sha256:${"b".repeat(64)}`;

function bundleFor(image, predicateType, predicate) {
  return { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", dsseEnvelope: {
    payloadType: "application/vnd.in-toto+json", signatures: [{ sig: "test-signature" }],
    payload: Buffer.from(JSON.stringify({ _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: image, digest: { sha256: digest.slice(7) } }], predicateType, predicate,
    })).toString("base64"),
  } };
}

async function fixture(fn, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), "attest-image-"));
  const predicate = { buildDefinition: { resolvedDependencies: [{
    name: "release-candidate", digest: { gitCommit: "c".repeat(40) },
  }] } };
  const predicatePath = join(directory, "predicate.json");
  writeFileSync(predicatePath, JSON.stringify(predicate));
  const image = options.image || "ghcr.io/example/router";
  const predicateType = options.predicateType || PREDICATE_TYPE;
  const bundle = bundleFor(image, predicateType, predicate);
  const calls = [];
  const run = (command, args) => {
    calls.push({ command, args });
    if (options.fail === calls.length) throw new Error("verification failed");
    if (args[0] === "attest") {
      writeFileSync(args[args.indexOf("--bundle") + 1], JSON.stringify(bundle));
    }
    return JSON.stringify([{ attestation: { bundle } }]);
  };
  const github = { request: async (route, body) => {
    calls.push({ route, body });
    if (options.fail === calls.length) throw new Error("upload failed");
    return { status: 201, data: { id: 1 } };
  } };
  try {
    await fn({ directory, predicatePath, predicate, image, predicateType, context, digest,
      label: options.label || "ghcr-provenance", bundle, calls, run, github });
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test("each registry and predicate is verified before GitHub upload and discovery", async () => {
  for (const [image, prefix] of [["ghcr.io/example/router", "ghcr"], ["docker.io/example/router", "dockerhub"]]) {
    for (const [predicateType, kind] of [[PREDICATE_TYPE, "provenance"], [SBOM_TYPE, "sbom"]]) {
      await fixture(async state => {
        const path = await attestImage(state);
        assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), state.bundle);
        assert.equal(state.calls.length, 5);
        assert.deepEqual(state.calls[0].args.slice(0, 2), ["attest", "--yes"]);
        assert.equal(state.calls[0].args.at(-1), `${image}@${digest}`);
        const local = state.calls[1].args;
        assert.equal(local[local.indexOf("--source-digest") + 1], context.sha);
        assert.equal(local[local.indexOf("--source-ref") + 1], context.ref);
        assert.equal(local[local.indexOf("--predicate-type") + 1], predicateType);
        assert.equal(local[local.indexOf("--signer-workflow") + 1], "example/router/.github/workflows/publish.yml");
        assert.ok(local.includes("--bundle"));
        assert.ok(state.calls[2].args.includes("--bundle-from-oci"));
        assert.equal(state.calls[3].route, "POST /repos/{owner}/{repo}/attestations");
        assert.deepEqual(state.calls[3].body.bundle, state.bundle);
        assert.equal(state.calls[4].command, "gh");
        assert.ok(!state.calls[4].args.includes("--bundle"));
      }, { image, predicateType, label: `${prefix}-${kind}` });
    }
  }
});

test("signing, verification and API failures block all following publication steps", async () => {
  for (const fail of [1, 2, 3, 4, 5]) {
    await fixture(async state => {
      await assert.rejects(attestImage(state), /failed/);
      assert.equal(state.calls.length, fail);
    }, { fail });
  }
});

test("signed statements must bind the exact digest, registry, type and candidate predicate", () => fixture(async state => {
  for (const mutate of [
    statement => { statement.subject[0].digest.sha256 = "d".repeat(64); },
    statement => { statement.subject[0].name = "ghcr.io/attacker/router"; },
    statement => { statement.subject.push(statement.subject[0]); },
    statement => { statement.predicateType = SBOM_TYPE; },
    statement => { statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = context.sha; },
  ]) {
    const bundle = structuredClone(state.bundle);
    const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString());
    mutate(statement);
    bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
    assert.throws(() => validateStatement(bundle, state.image, digest, PREDICATE_TYPE, state.predicate), /differs/);
  }
  state.bundle.dsseEnvelope.payload = Buffer.from("{}").toString("base64");
  await assert.rejects(attestImage(state), /differs/);
  assert.equal(state.calls.length, 2, "no registry validation or upload after a mismatched local bundle");
}));

test("discovery must return the freshly signed bundle, including on release retries", () => fixture(async state => {
  const run = state.run;
  state.run = (command, args) => {
    const output = run(command, args);
    if (args.includes("--bundle-from-oci")) {
      const results = JSON.parse(output);
      results[0].attestation.bundle.dsseEnvelope.signatures[0].sig = "older-signature";
      return JSON.stringify(results);
    }
    return output;
  };
  await assert.rejects(attestImage(state), /differs from the uploaded bundle/);
  assert.equal(state.calls.length, 3, "registry mismatch must prevent GitHub upload");
}));

test("invalid release inputs fail before signing", () => fixture(async state => {
  for (const invalid of [
    { digest: "latest" }, { image: "--insecure" }, { label: "../escape" },
    { predicateType: "https://example.invalid/other" },
    { context: { ...context, ref: "refs/heads/unreviewed" } },
    { context: { ...context, sha: "main" } },
  ]) await assert.rejects(attestImage({ ...state, ...invalid }), /Invalid release attestation input/);
  assert.deepEqual(state.calls, []);
}));

test("real subprocess verification captures a CycloneDX result larger than the default pipe buffer", () => {
  const output = execute(process.execPath, ["-e", `
    const predicate = { bomFormat: "CycloneDX", components: Array.from({ length: 5000 }, (_, index) => ({
      type: "library", name: "component-" + index, version: "1.0.0", description: "x".repeat(100),
    })) };
    const statement = { predicateType: "https://cyclonedx.org/bom", predicate };
    const bundle = { dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString("base64") } };
    process.stdout.write(JSON.stringify([{ attestation: { bundle }, verificationResult: { statement } }]));
  `]);
  assert.ok(Buffer.byteLength(output) > 1024 * 1024);
  const result = JSON.parse(output)[0];
  const encoded = JSON.parse(Buffer.from(result.attestation.bundle.dsseEnvelope.payload, "base64").toString());
  assert.deepEqual(encoded, result.verificationResult.statement);
  assert.equal(encoded.predicate.components.length, 5000);
});
