const { readFileSync, mkdirSync, mkdtempSync, openSync, closeSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const { execFileSync } = require("node:child_process");
const { isDeepStrictEqual } = require("node:util");
const { ISSUER, PREDICATE_TYPE } = require("./provenance.cjs");

const SBOM_TYPE = "https://cyclonedx.org/bom";

/** @typedef {{mediaType: string, dsseEnvelope: {payloadType: string, payload: string, [key: string]: unknown}, [key: string]: unknown}} AttestationBundle */
/** @typedef {{repo: {owner: string, repo: string}, ref: string, sha: string}} AttestationContext */
/** @typedef {(command: string, args: string[]) => string} CommandRunner */
/** @typedef {{request(route: string, body: {owner: string, repo: string, bundle: AttestationBundle}): Promise<{status: number}>}} AttestationClient */

/** @type {CommandRunner} */
function execute(command, args) {
  // Verification includes both the decoded SBOM and its base64 bundle. Capture
  // stdout on disk so legitimate large SBOMs do not hit execFileSync's 1 MiB limit.
  const directory = mkdtempSync(join(tmpdir(), "release-attestation-"));
  const output = join(directory, "stdout");
  const descriptor = openSync(output, "wx", 0o600);
  try {
    execFileSync(command, args, { stdio: ["ignore", descriptor, "pipe"] });
    return readFileSync(output, "utf8");
  } catch (cause) {
    throw new Error(`${command} ${args[0]} failed`, { cause });
  } finally {
    closeSync(descriptor);
    rmSync(directory, { recursive: true, force: true });
  }
}

/**
 * @param {unknown} bundle
 * @param {string} image
 * @param {string} digest
 * @param {string} predicateType
 * @param {unknown} predicate
 * @returns {asserts bundle is AttestationBundle}
 */
function validateStatement(bundle, image, digest, predicateType, predicate) {
  if (typeof bundle !== "object" || bundle === null || !("mediaType" in bundle) ||
      bundle.mediaType !== "application/vnd.dev.sigstore.bundle.v0.3+json" ||
      !("dsseEnvelope" in bundle) || typeof bundle.dsseEnvelope !== "object" || bundle.dsseEnvelope === null ||
      !("payloadType" in bundle.dsseEnvelope) || bundle.dsseEnvelope.payloadType !== "application/vnd.in-toto+json" ||
      !("payload" in bundle.dsseEnvelope) || typeof bundle.dsseEnvelope.payload !== "string") {
    throw new Error("Expected a Sigstore v0.3 DSSE bundle");
  }
  /** @type {unknown} */
  const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  if (typeof statement !== "object" || statement === null || !("subject" in statement) ||
      !Array.isArray(statement.subject) || statement.subject.length !== 1) {
    throw new Error("Attestation differs from the release subject or predicate");
  }
  /** @type {unknown} */
  const subject = statement.subject[0];
  const canonicalImage = image.replace(/^docker\.io\//, "index.docker.io/");
  if (!("_type" in statement) || typeof statement._type !== "string" ||
      !["https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"].includes(statement._type) ||
      typeof subject !== "object" || subject === null || !("name" in subject) || typeof subject.name !== "string" ||
      ![image, canonicalImage].includes(subject.name) || !("digest" in subject) ||
      !isDeepStrictEqual(subject.digest, { sha256: digest.slice("sha256:".length) }) ||
      !("predicateType" in statement) || statement.predicateType !== predicateType ||
      !("predicate" in statement) || !isDeepStrictEqual(statement.predicate, predicate)) {
    throw new Error("Attestation differs from the release subject or predicate");
  }
}

/** @param {string} output @param {AttestationBundle} bundle @returns {void} */
function verifyDiscoveredBundle(output, bundle) {
  /** @type {unknown} */
  const results = JSON.parse(output);
  if (!Array.isArray(results) || !results.some((/** @type {unknown} */ result) =>
    typeof result === "object" && result !== null && "attestation" in result &&
    typeof result.attestation === "object" && result.attestation !== null && "bundle" in result.attestation &&
    typeof result.attestation.bundle === "object" && result.attestation.bundle !== null &&
    "dsseEnvelope" in result.attestation.bundle &&
    isDeepStrictEqual(result.attestation.bundle.dsseEnvelope, bundle.dsseEnvelope))) {
    throw new Error("Verified registry or GitHub attestation differs from the uploaded bundle");
  }
}

/**
 * @param {{github: AttestationClient, context: AttestationContext, image: string, digest: string, predicatePath: string,
 *   predicateType: string, label: string, run?: CommandRunner, directory?: string}} options
 * @returns {Promise<string>}
 */
async function attestImage({ github, context, image, digest, predicatePath, predicateType, label,
  run = execute, directory = join(/** @type {string} */ (process.env.RUNNER_TEMP), "attestations") }) {
  const repository = `${context.repo.owner}/${context.repo.repo}`;
  if (!/^sha256:[a-f0-9]{64}$/.test(digest) ||
      !/^ghcr-(provenance|sbom)$|^dockerhub-(provenance|sbom)$/.test(label) ||
      ![PREDICATE_TYPE, SBOM_TYPE].includes(predicateType) ||
      !/^([a-z0-9.-]+\/)\S+$/.test(image) || context.ref !== "refs/heads/main" ||
      !/^[a-f0-9]{40}$/.test(context.sha)) {
    throw new Error("Invalid release attestation input");
  }
  /** @type {unknown} */
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
  /** @type {unknown} */
  const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
  validateStatement(bundle, image, digest, predicateType, predicate);
  verifyDiscoveredBundle(run("gh", [...verify, "--bundle-from-oci"]), bundle);
  const response = await github.request("POST /repos/{owner}/{repo}/attestations", { ...context.repo, bundle });
  if (response.status !== 201) throw new Error("GitHub did not create the attestation");
  verifyDiscoveredBundle(run("gh", verify), bundle);
  return bundlePath;
}

module.exports = { attestImage, validateStatement, execute, SBOM_TYPE };
