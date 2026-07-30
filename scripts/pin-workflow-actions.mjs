import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const workflowDir = ".github/workflows";
const replacements = new Map([
  ["actions/checkout@v4", "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4"],
  ["step-security/harden-runner@v2", "step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920 # v2"],
  ["actions/setup-node@v6", "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6"],
  ["github/codeql-action/upload-sarif@v3", "github/codeql-action/upload-sarif@4187e74d05793876e9989daffde9c3e66b4acd07 # v3"],
  ["github/codeql-action/init@v3", "github/codeql-action/init@4187e74d05793876e9989daffde9c3e66b4acd07 # v3"],
  ["github/codeql-action/analyze@v3", "github/codeql-action/analyze@4187e74d05793876e9989daffde9c3e66b4acd07 # v3"],
  ["gitleaks/gitleaks-action@v3", "gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e # v3"],
  ["hadolint/hadolint-action@v3.3.0", "hadolint/hadolint-action@2332a7b74a6de0dda2e2221d575162eba76ba5e5 # v3.3.0"],
  ["dependabot/fetch-metadata@v2", "dependabot/fetch-metadata@21025c705c08248db411dc16f3619e6b5f9ea21a # v2"],
  ["actions/github-script@v9", "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9"],
  ["docker/setup-buildx-action@v4", "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4"],
  ["docker/build-push-action@v7", "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7"],
  ["aquasecurity/trivy-action@v0.36.0", "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0"],
  ["docker/login-action@v4", "docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4"],
  ["sigstore/cosign-installer@v3", "sigstore/cosign-installer@398d4b0eeef1380460a10c8013a76f728fb906ac # v3"],
  ["actions/attest-build-provenance@v2", "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be # v2"],
]);

for (const name of await readdir(workflowDir)) {
  if (!name.endsWith(".yml") && !name.endsWith(".yaml")) continue;
  const path = join(workflowDir, name);
  const original = await readFile(path, "utf8");
  let updated = original;
  for (const [tag, pinned] of replacements) {
    updated = updated.replaceAll(tag, pinned);
  }
  if (updated !== original) await writeFile(path, updated);
}
