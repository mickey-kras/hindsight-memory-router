const { readFileSync, mkdirSync } = require("node:fs");
const { join } = require("node:path");
const { execFileSync } = require("node:child_process");
const { isDeepStrictEqual } = require("node:util");
const { ISSUER, PREDICATE_TYPE } = require("./provenance.cjs");

const SBOM_TYPE = "https://cyclonedx.org/bom";

/**
 * @typedef {{payloadType: string, payload: string, signatures: {sig: string, keyid?: string}[]}} Envelope
 * @typedef {{mediaType: string, dsseEnvelope: Envelope}} Bundle
 * @typedef {{repo: {owner: string, repo: string}, ref: string, sha: string}} Context
 * @typedef {{github: {request(route: string, body: {owner: string, repo: string, bundle: Bundle}):
 * Promise<{status: number}>}, context: Context, image: string, digest: string, predicatePath: string,
 * predicateType: string, label: string, run?: (command: string, args: string[]) => string, directory?: string}} AttestOptions
 */

/** @param {string} command @param {string[]} args */
function execute(command, args) {
  // Do not print attestation payloads or command failures containing captured output.
  try { return execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); }
  catch (cause) { throw new Error(`${command} ${args[0]} failed`, { cause }); }
}

/** @param {Bundle} bundle @param {string} image @param {string} digest
 * @param {string} predicateType @param {unknown} predicate */
function validateStatement(bundle, image, digest, predicateType, predicate) {
  if (bundle.mediaType !== "application/vnd.dev.sigstore.bundle.v0.3+json" ||
      bundle.dsseEnvelope?.payloadType !== "application/vnd.in-toto+json") {
    throw new Error("Expected a Sigstore v0.3 DSSE bundle");
  }
  const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  const subject = statement.subject?.[0];
  const canonicalImage = image.replace(/^docker\.io\//, "index.docker.io/");
  if (!["https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"].includes(statement._type) || statement.subject.length !== 1 ||
      ![image, canonicalImage].includes(subject?.name) ||
      !isDeepStrictEqual(subject?.digest, { sha256: digest.slice("sha256:".length) }) ||
      statement.predicateType !== predicateType || !isDeepStrictEqual(statement.predicate, predicate)) {
    throw new Error("Attestation differs from the release subject or predicate");
  }
}

/** @param {string} output @param {Bundle} bundle */
function verifyDiscoveredBundle(output, bundle) {
  const results = JSON.parse(output);
  if (!Array.isArray(results) || !results.some(result =>
    isDeepStrictEqual(result.attestation?.bundle?.dsseEnvelope, bundle.dsseEnvelope))) {
    throw new Error("Verified registry or GitHub attestation differs from the uploaded bundle");
  }
}

/** @param {AttestOptions} options */
async function attestImage({ github, context, image, digest, predicatePath, predicateType, label,
  run = execute, directory = join(process.env.RUNNER_TEMP, "attestations") }) {
  const repository = `${context.repo.owner}/${context.repo.repo}`;
  if (!/^sha256:[a-f0-9]{64}$/.test(digest) ||
      !/^ghcr-(provenance|sbom)$|^dockerhub-(provenance|sbom)$/.test(label) ||
      ![PREDICATE_TYPE, SBOM_TYPE].includes(predicateType) ||
      !/^([a-z0-9.-]+\/)\S+$/.test(image) || context.ref !== "refs/heads/main" ||
      !/^[a-f0-9]{40}$/.test(context.sha)) {
    throw new Error("Invalid release attestation input");
  }
  const predicate = JSON.parse(readFileSync(predicatePath, "utf8"));
  const subject = `${image}@${digest}`;
  const signer = `${repository}/.github/workflows/publish.yml`;
  const verify = ["attestation", "verify", `oci://${subject}`, "--repo", repository,
    "--signer-workflow", signer, "--source-digest", context.sha, "--source-ref", context.ref,
    "--cert-oidc-issuer", ISSUER, "--predicate-type", predicateType, "--format", "json"];
  mkdirSync(directory, { recursive: true });
  const bundlePath = join(directory, `${label}.sigstore.json`);
  run("cosign", ["attest", "--yes", "--predicate", predicatePath, "--type", predicateType,
    "--bundle", bundlePath, subject]);
  run("gh", [...verify, "--bundle", bundlePath]);
  const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
  validateStatement(bundle, image, digest, predicateType, predicate);
  verifyDiscoveredBundle(run("gh", [...verify, "--bundle-from-oci"]), bundle);
  const response = await github.request("POST /repos/{owner}/{repo}/attestations", { ...context.repo, bundle });
  if (response.status !== 201) throw new Error("GitHub did not create the attestation");
  verifyDiscoveredBundle(run("gh", verify), bundle);
  return bundlePath;
}

module.exports = { attestImage, validateStatement, SBOM_TYPE };
