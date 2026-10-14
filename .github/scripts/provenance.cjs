const ISSUER = "https://token.actions.githubusercontent.com";
const AUDIENCE = "nobody";
const PREDICATE_TYPE = "https://slsa.dev/provenance/v1";
/** @typedef {"ref" | "sha" | "repository" | "event_name" | "job_workflow_ref" | "workflow_ref" | "repository_id" | "repository_owner_id" | "runner_environment" | "run_id" | "run_attempt"} ClaimName */
/** @typedef {import("jose").JWTPayload & Record<ClaimName, string>} GitHubClaims */
/** @typedef {{repo: {owner: string, repo: string}, ref: string, sha: string, eventName: string, runId: number}} WorkflowContext */
/**
 * @typedef {object} ProvenancePredicate
 * @property {string} type
 * @property {{buildDefinition: {
 *   buildType: string,
 *   externalParameters: {workflow: {ref: string, repository: string, path: string}},
 *   internalParameters: {github: {event_name: string, repository_id: string, repository_owner_id: string, runner_environment: string}},
 *   resolvedDependencies: {uri: string, digest: {gitCommit: string}}[]
 * }, runDetails: {builder: {id: string}, metadata: {invocationId: string}}}} params
 */
/** @type {ClaimName[]} */
const CLAIMS = ["ref", "sha", "repository", "event_name", "job_workflow_ref", "workflow_ref",
  "repository_id", "repository_owner_id", "runner_environment", "run_id", "run_attempt"];

/**
 * @param {string} token
 * @param {import("jose").JWTVerifyGetKey} keys
 * @returns {Promise<GitHubClaims>}
 */
async function verifyClaims(token, keys) {
  const { jwtVerify } = await import("jose");
  const { payload } = await jwtVerify(token, keys, {
    issuer: ISSUER, audience: AUDIENCE, algorithms: ["RS256"],
    requiredClaims: ["exp", "iat", ...CLAIMS],
  });
  for (const name of CLAIMS) {
    if (typeof payload[name] !== "string" || payload[name].length === 0) {
      throw new Error(`Invalid OIDC claim: ${name}`);
    }
  }
  return /** @type {GitHubClaims} */ (payload);
}

/** @returns {Promise<import("jose").JWTVerifyGetKey>} */
async function githubKeys() {
  const response = await fetch(`${ISSUER}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`OIDC discovery failed: ${response.status}`);
  /** @type {unknown} */
  const config = await response.json();
  if (typeof config !== "object" || config === null || !("issuer" in config) ||
      config.issuer !== ISSUER || !("jwks_uri" in config) || typeof config.jwks_uri !== "string" ||
      new URL(config.jwks_uri).origin !== ISSUER) {
    throw new Error("Invalid GitHub OIDC discovery document");
  }
  const { createRemoteJWKSet } = await import("jose");
  return createRemoteJWKSet(new URL(config.jwks_uri));
}

/**
 * @param {{core: {getIDToken(audience: string): Promise<string>}, context: WorkflowContext, keys?: import("jose").JWTVerifyGetKey}} options
 * @returns {Promise<ProvenancePredicate>}
 */
async function buildProvenance({ core, context, keys }) {
  const claims = await verifyClaims(await core.getIDToken(AUDIENCE), keys || await githubKeys());
  const repository = `${context.repo.owner}/${context.repo.repo}`;
  /** @type {Partial<Record<ClaimName, string | undefined>>} */
  const expected = {
    repository, ref: context.ref, sha: context.sha, event_name: context.eventName,
    workflow_ref: `${repository}/.github/workflows/release.yml@${context.ref}`,
    job_workflow_ref: `${repository}/.github/workflows/publish.yml@${context.ref}`,
    run_id: String(context.runId), run_attempt: process.env.GITHUB_RUN_ATTEMPT,
  };
  for (const [name, value] of Object.entries(expected)) {
    if (!value || claims[name] !== value) throw new Error(`OIDC claim differs from executing workflow: ${name}`);
  }
  if (context.ref !== "refs/heads/main" || !/^[a-f0-9]{40}$/.test(context.sha)) {
    throw new Error("Provenance requires an immutable main workflow source");
  }
  const server = "https://github.com";
  return {
    type: PREDICATE_TYPE,
    params: {
      buildDefinition: {
        buildType: "https://actions.github.io/buildtypes/workflow/v1",
        externalParameters: { workflow: {
          ref: claims.ref, repository: `${server}/${repository}`, path: ".github/workflows/release.yml",
        } },
        internalParameters: { github: {
          event_name: claims.event_name, repository_id: claims.repository_id,
          repository_owner_id: claims.repository_owner_id, runner_environment: claims.runner_environment,
        } },
        resolvedDependencies: [{ uri: `git+${server}/${repository}@${claims.ref}`, digest: { gitCommit: claims.sha } }],
      },
      runDetails: {
        builder: { id: `${server}/${claims.job_workflow_ref}` },
        metadata: { invocationId: `${server}/${repository}/actions/runs/${claims.run_id}/attempts/${claims.run_attempt}` },
      },
    },
  };
}

module.exports = { buildProvenance, verifyClaims, ISSUER, AUDIENCE, PREDICATE_TYPE };
