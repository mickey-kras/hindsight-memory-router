// Removes the orphaned state of a failed release run: the registry tags the
// run pushed (GHCR and Docker Hub, including cosign/attestation artifacts) and
// the protected release branch. Strictly scoped to the exact version tag, the
// commit-sha tag, and referrers of this run's digest. Never touches latest,
// other versions, or anything an existing git tag/release still references.
// Every target is best-effort: failures are logged, never thrown, so cleanup
// can never mask the original release failure.

const releaseTag = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const commitSha = /^[a-f0-9]{40}$/;
const imageDigest = /^sha256:[a-f0-9]{64}$/;
const ghcrRepository = /^ghcr\.io\/([a-z0-9-]+\/[a-z0-9._-]+)$/;
const hubRepository = /^docker\.io\/([a-z0-9]+\/[a-z0-9._-]+)$/;

class CleanupError extends Error {}

function requireValue(condition, message) {
  if (!condition) throw new CleanupError(message);
}

function targets(context) {
  requireValue(
    context.eventName === "push" && context.workflow === "release" &&
      context.ref.startsWith("refs/heads/release/"),
    "Cleanup is allowed only through the release workflow",
  );
  const version = context.ref.slice("refs/heads/release/".length);
  requireValue(releaseTag.test(`v${version}`), "Invalid release branch version");
  requireValue(commitSha.test(context.sha), "Invalid release commit");
  return { version, sha: context.sha };
}

async function published(github, repository, version) {
  const absent = (error) => {
    if (error.status === 404) return false;
    throw error;
  };
  const tag = await github.rest.git.getRef({ ...repository, ref: `tags/v${version}` }).then(() => true, absent);
  const release = await github.rest.repos.getReleaseByTag({ ...repository, tag: `v${version}` }).then(() => true, absent);
  return tag || release;
}

function artifactTags(digests) {
  const tags = new Set();
  for (const digest of digests) {
    requireValue(imageDigest.test(digest), "Invalid published image digest");
    tags.add(`${digest.replace(":", "-")}.sig`);
    tags.add(`${digest.replace(":", "-")}.att`);
  }
  return tags;
}

function runDigest() {
  const digest = process.env.CLEANUP_DIGEST || "";
  requireValue(!digest || imageDigest.test(digest), "Invalid CLEANUP_DIGEST");
  return digest;
}

async function attempt(core, summary, name, action) {
  try {
    const removed = await action();
    const detail = removed.length ? `deleted ${removed.map((tag) => `\`${tag}\``).join(", ")}` : "nothing left to delete";
    await summary.addRaw(`- ${name}: ${detail}\n`);
  } catch (error) {
    core.error(`${name} cleanup failed: ${error.message}`);
    await summary.addRaw(`- ${name}: **failed** (${error.message}); remove the orphaned tags manually\n`);
  }
}

function ghcrPackages(github, context) {
  const parameters = { package_type: "container", package_name: context.repo.repo, per_page: 100 };
  if (context.payload.repository?.owner?.type === "Organization") {
    return {
      list: () =>
        github.paginate(github.rest.packages.getAllPackageVersionsForPackageOwnedByOrg, {
          ...parameters,
          org: context.repo.owner,
        }),
      remove: (id) =>
        github.rest.packages.deletePackageVersionForOrg({ ...parameters, org: context.repo.owner, package_version_id: id }),
    };
  }
  return {
    list: () => github.paginate(github.rest.packages.getAllPackageVersionsForPackageOwnedByAuthenticatedUser, parameters),
    remove: (id) => github.rest.packages.deletePackageVersionForAuthenticatedUser({ ...parameters, package_version_id: id }),
  };
}

async function ghcrReferrers(context, repository, digest, fetchImpl) {
  const credentials = Buffer.from(`${context.actor}:${process.env.GITHUB_TOKEN}`).toString("base64");
  const tokenResponse = await fetchImpl(`https://ghcr.io/token?scope=repository:${repository}:pull`, {
    headers: { authorization: `Basic ${credentials}` },
  });
  if (!tokenResponse.ok) throw new CleanupError(`GHCR token request failed: ${tokenResponse.status}`);
  const { token } = await tokenResponse.json();
  const response = await fetchImpl(`https://ghcr.io/v2/${repository}/referrers/${digest}`, {
    headers: { authorization: `Bearer ${token}`, accept: "application/vnd.oci.image.index.v1+json" },
  });
  if (response.status === 404) return [];
  if (!response.ok) throw new CleanupError(`GHCR referrer request failed: ${response.status}`);
  const index = await response.json();
  return (index.manifests ?? []).map((item) => item.digest).filter((item) => imageDigest.test(item));
}

async function cleanupGhcr(github, context, core, version, sha, fetchImpl) {
  const match = ghcrRepository.exec(process.env.IMAGE_GHCR || "");
  requireValue(match, "Set IMAGE_GHCR to the GHCR repository");
  const wanted = new Set([version, sha]);
  const digest = runDigest();
  const packages = ghcrPackages(github, context);
  const versions = await packages.list();
  const tagged = (item) => item.metadata?.container?.tags ?? [];
  const foreign = new Set();
  let subjects = versions.filter((item) => tagged(item).some((tag) => wanted.has(tag)));
  if (digest) {
    const stale = subjects.filter((item) => item.name !== digest);
    for (const item of stale) foreign.add(item.id);
    if (stale.length) core.warning(`GHCR tags for ${version} now resolve to another digest; a newer attempt owns them`);
    subjects = subjects.filter((item) => item.name === digest);
  }
  const artifacts = artifactTags(subjects.map((item) => item.name));
  const referrers = new Set();
  for (const subject of subjects) {
    for (const item of await ghcrReferrers(context, match[1], subject.name, fetchImpl)) referrers.add(item);
  }
  const removed = [];
  for (const item of versions) {
    const tags = tagged(item);
    const owned = !foreign.has(item.id) && tags.length > 0 && tags.every((tag) => wanted.has(tag) || artifacts.has(tag));
    const ownedReferrer = tags.length === 0 && referrers.has(item.name);
    if (!owned && !ownedReferrer) continue;
    try {
      await packages.remove(item.id);
      removed.push(tags.length ? tags.join(", ") : `${item.name} (referrer)`);
    } catch (error) {
      if (error.status !== 404) throw error;
    }
  }
  return removed;
}

async function hubRequest(fetchImpl, url, options, allowMissing = false) {
  const response = await fetchImpl(url, options);
  if (allowMissing && response.status === 404) return null;
  if (!response.ok) throw new CleanupError(`Docker Hub request failed: ${response.status} (${url})`);
  return response;
}

async function cleanupDockerHubReferrers(core, repository, credentials, digests, fetchImpl) {
  try {
    const tokenResponse = await hubRequest(
      fetchImpl,
      `https://auth.docker.io/token?service=registry.docker.com&scope=repository:${repository}:pull,delete`,
      { headers: { authorization: `Basic ${credentials}` } },
    );
    const { token } = await tokenResponse.json();
    const headers = { authorization: `Bearer ${token}`, accept: "application/vnd.oci.image.index.v1+json" };
    const removed = [];
    for (const digest of digests) {
      const response = await fetchImpl(`https://registry-1.docker.io/v2/${repository}/referrers/${digest}`, { headers });
      if (!response.ok) continue;
      const index = await response.json();
      for (const item of (index.manifests ?? []).filter((entry) => imageDigest.test(entry.digest ?? ""))) {
        const deletion = await fetchImpl(`https://registry-1.docker.io/v2/${repository}/manifests/${item.digest}`, {
          method: "DELETE",
          headers,
        });
        if (deletion.ok || deletion.status === 404) removed.push(`${item.digest} (referrer)`);
      }
    }
    return removed;
  } catch (error) {
    core.warning(`Docker Hub referrer cleanup skipped: ${error.message}`);
    return [];
  }
}

async function cleanupDockerHub(core, version, sha, fetchImpl) {
  const match = hubRepository.exec(process.env.IMAGE_DOCKERHUB || "");
  requireValue(match, "Set IMAGE_DOCKERHUB to the Docker Hub repository");
  const username = process.env.DOCKERHUB_USERNAME;
  const password = process.env.DOCKERHUB_TOKEN;
  requireValue(username && password, "Set DOCKERHUB_USERNAME and DOCKERHUB_TOKEN");
  const credentials = Buffer.from(`${username}:${password}`).toString("base64");
  const login = await hubRequest(fetchImpl, "https://hub.docker.com/v2/users/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const { token } = await login.json();
  requireValue(typeof token === "string" && token.length > 0, "Docker Hub login returned no token");
  const repository = match[1];
  const api = `https://hub.docker.com/v2/repositories/${repository}/tags`;
  const headers = { authorization: `JWT ${token}` };
  const wanted = [version, sha];
  const digest = runDigest();
  const digests = [];
  const candidates = [];
  for (const tag of wanted) {
    const detail = await hubRequest(fetchImpl, `${api}/${tag}`, { headers }, true);
    if (!detail) continue;
    const body = await detail.json();
    if (digest && body.digest !== digest) {
      core.warning(`Docker Hub tag ${tag} now resolves to another digest; a newer attempt owns it`);
      continue;
    }
    candidates.push(tag);
    if (imageDigest.test(body.digest ?? "")) digests.push(body.digest);
  }
  const removed = await cleanupDockerHubReferrers(core, repository, credentials, digests, fetchImpl);
  for (const tag of [...candidates, ...artifactTags(digests)]) {
    const deletion = await fetchImpl(`${api}/${tag}`, { method: "DELETE", headers });
    if (deletion.status === 404) continue;
    if (!deletion.ok) throw new CleanupError(`Docker Hub tag deletion failed: ${deletion.status} (${tag})`);
    removed.push(tag);
  }
  return removed;
}

async function registries({ github, context, core, fetchImpl = fetch }) {
  // Fail-safe entry guards (targets(), the published() probe) throw before any
  // deletion; still leave a summary line so the run page shows why nothing ran.
  const summary = core.summary.addHeading("Failed release cleanup: registry tags", 3);
  try {
    const { version, sha } = targets(context);
    summary.addRaw(`Version \`${version}\`, commit \`${context.sha}\`.\n\n`);
    if (await published(github, context.repo, version)) {
      await summary
        .addRaw(`\`v${version}\` already has a git tag or release; keeping every registry tag. Re-run failed jobs to finish the release.\n`)
        .write();
      return;
    }
    await attempt(core, summary, "GHCR", () => cleanupGhcr(github, context, core, version, sha, fetchImpl));
    await attempt(core, summary, "Docker Hub", () => cleanupDockerHub(core, version, sha, fetchImpl));
    await summary.write();
  } catch (error) {
    await summary.addRaw(`Aborted before any deletion: ${error.message}\n`).write();
    throw error;
  }
}

async function branch({ github, context, core }) {
  const { version } = targets(context);
  const summary = core.summary.addHeading("Failed release cleanup: branch", 3);
  if (await published(github, context.repo, version)) {
    await summary
      .addRaw(`Kept \`release/${version}\`: \`v${version}\` already exists. Re-run failed jobs to finish the release.\n`)
      .write();
    return;
  }
  const ref = `heads/release/${version}`;
  const current = await github.rest.git.getRef({ ...context.repo, ref }).then(
    ({ data }) => data,
    (error) => {
      if (error.status === 404) return null;
      throw error;
    },
  );
  if (!current) {
    await summary.addRaw(`Branch \`release/${version}\` is already absent.\n`).write();
    return;
  }
  if (current.object.sha !== context.sha) {
    await summary
      .addRaw(`Kept \`release/${version}\`: the branch advanced past the failed run; its newest attempt owns it.\n`)
      .write();
    return;
  }
  await attempt(core, summary, `Branch \`release/${version}\``, async () => {
    await github.rest.git.deleteRef({ ...context.repo, ref });
    return [ref];
  });
  await summary.write();
}

async function preparation({ github, context, core }) {
  requireValue(
    context.eventName === "workflow_dispatch" && context.ref === "refs/heads/main",
    "Preparation cleanup is allowed only from the main workflow button",
  );
  const summary = core.summary.addHeading("Failed release cleanup: preparation branches", 3);
  const branches = await github.paginate(github.rest.repos.listBranches, { ...context.repo, per_page: 100 });
  for (const item of branches.filter((branch) => branch.name.startsWith("release/"))) {
    const version = item.name.slice("release/".length);
    if (!releaseTag.test(`v${version}`)) continue;
    const file = await github.rest.repos
      .getContent({ ...context.repo, path: "release.json", ref: item.name })
      .then(
        ({ data }) => data,
        (error) => {
          if (error.status === 404) return null;
          throw error;
        },
      );
    if (!file || file.type !== "file" || file.encoding !== "base64") continue;
    const manifest = JSON.parse(Buffer.from(file.content, "base64").toString("utf8"));
    if (manifest.preparation_run !== context.runId) continue;
    if (await published(github, context.repo, version)) {
      await summary.addRaw(`Kept \`${item.name}\`: \`v${version}\` already has a git tag or release.\n`);
      continue;
    }
    await attempt(core, summary, `Branch \`${item.name}\``, async () => {
      await github.rest.git.deleteRef({ ...context.repo, ref: `heads/${item.name}` });
      return [item.name];
    });
  }
  await summary.write();
}

module.exports = {
  CleanupError,
  targets,
  published,
  artifactTags,
  attempt,
  cleanupGhcr,
  cleanupDockerHub,
  registries,
  branch,
  preparation,
};
