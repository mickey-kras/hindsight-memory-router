const test = require("node:test");
const assert = require("node:assert/strict");
const { buildProvenance, verifyClaims, ISSUER, AUDIENCE } = require("./provenance.cjs");

const context = {
  repo: { owner: "example", repo: "router" }, ref: "refs/heads/main", sha: "a".repeat(40),
  eventName: "workflow_dispatch", runId: 123,
};
const claims = {
  ref: context.ref, sha: context.sha, repository: "example/router", event_name: context.eventName,
  job_workflow_ref: "example/router/.github/workflows/publish.yml@refs/heads/main",
  workflow_ref: "example/router/.github/workflows/release.yml@refs/heads/main",
  repository_id: "1", repository_owner_id: "2", runner_environment: "github-hosted",
  run_id: "123", run_attempt: "1",
};

async function fixture(fn) {
  const { generateKeyPair, SignJWT, exportJWK, createLocalJWKSet } = await import("jose");
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const keys = createLocalJWKSet({ keys: [await exportJWK(publicKey)] });
  const sign = (payload = claims, issuer = ISSUER, audience = AUDIENCE, expiration = "2m") =>
    new SignJWT(payload).setProtectedHeader({ alg: "RS256" }).setIssuer(issuer).setAudience(audience)
      .setIssuedAt().setExpirationTime(expiration).sign(privateKey);
  await fn({ keys, sign });
}

test("signed GitHub claims map to workflow provenance without conflating the candidate", () => fixture(async ({ keys, sign }) => {
  const previous = process.env.GITHUB_RUN_ATTEMPT;
  process.env.GITHUB_RUN_ATTEMPT = "1";
  try {
    const token = await sign();
    const core = { getIDToken: async audience => { assert.equal(audience, AUDIENCE); return token; } };
    const result = await buildProvenance({ core, context, keys });
    assert.deepEqual(result.params.buildDefinition.resolvedDependencies, [{
      uri: "git+https://github.com/example/router@refs/heads/main", digest: { gitCommit: context.sha },
    }]);
    assert.deepEqual(result.params.buildDefinition.externalParameters.workflow, {
      ref: context.ref, repository: "https://github.com/example/router", path: ".github/workflows/release.yml",
    });
    assert.equal(result.params.runDetails.builder.id, `https://github.com/${claims.job_workflow_ref}`);
    assert.equal(result.params.runDetails.metadata.invocationId,
      "https://github.com/example/router/actions/runs/123/attempts/1");
    for (const [name, value] of Object.entries({
      repository: "attacker/router", ref: "refs/heads/other", sha: "b".repeat(40),
      event_name: "pull_request", job_workflow_ref: "example/router/.github/workflows/other.yml@refs/heads/main",
      workflow_ref: "example/router/.github/workflows/release.yml@refs/heads/other", run_id: "124", run_attempt: "2",
    })) {
      const bad = await sign({ ...claims, [name]: value });
      await assert.rejects(buildProvenance({ core: { getIDToken: async () => bad }, context, keys }), /differs from executing workflow/);
    }
  } finally {
    if (previous === undefined) delete process.env.GITHUB_RUN_ATTEMPT;
    else process.env.GITHUB_RUN_ATTEMPT = previous;
  }
}));

test("OIDC verification rejects forged signatures, wrong issuer/audience, expiry and malformed claims", () => fixture(async ({ keys, sign }) => {
  for (const token of [
    await sign(claims, `${ISSUER}.attacker.example`), await sign(claims, ISSUER, "sigstore"),
    await sign(claims, ISSUER, AUDIENCE, "-1s"),
    await sign({ ...claims, sha: 123 }), await sign({ ...claims, run_id: "" }),
  ]) await assert.rejects(verifyClaims(token, keys));
  const missing = { ...claims };
  delete missing.job_workflow_ref;
  await assert.rejects(verifyClaims(await sign(missing), keys), /missing required/);
  await fixture(async other => { await assert.rejects(verifyClaims(await other.sign(), keys), /signature verification failed/); });
  const parts = (await sign()).split(".");
  parts[1] = Buffer.from(JSON.stringify({ ...claims, sha: "b".repeat(40) })).toString("base64url");
  await assert.rejects(verifyClaims(parts.join("."), keys));
}));
