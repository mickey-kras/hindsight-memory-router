const { readFileSync, existsSync } = require("node:fs");
const { execFileSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");

class ReleaseError extends Error {}

const upstream = { owner: "vectorize-io", repo: "hindsight" };
const coreTag = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const releaseTag = coreTag;
const commitSha = /^[a-f0-9]{40}$/;
const imageDigest = /^sha256:[a-f0-9]{64}$/;

function requireValue(condition, message) {
  if (!condition) throw new ReleaseError(message);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function checksum(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

async function optional(request) {
  try {
    return (await request()).data;
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

function validatePin(pin) {
  requireValue(pin && coreTag.test(`v${pin.version}`), "Invalid Hindsight version");
  requireValue(commitSha.test(pin.sha), "Invalid Hindsight commit");
  const prefix = `ghcr.io/vectorize-io/hindsight:${pin.version}@`;
  requireValue(
    typeof pin.image === "string" && pin.image.startsWith(prefix) && imageDigest.test(pin.image.slice(prefix.length)),
    "Hindsight image must match its version and digest",
  );
  return pin;
}

async function retry(request, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))) {
  for (let attempt = 0; ; attempt++) {
    try { return await request(); }
    catch (error) {
      if (attempt === 2 || (error.status && error.status < 500 && error.status !== 429)) throw error;
      await sleep(1000 * 2 ** attempt);
    }
  }
}

async function latestHindsight(
  github,
  inspect = (image) =>
    JSON.parse(
      execFileSync("docker", ["buildx", "imagetools", "inspect", image, "--format", "{{json .Manifest.Digest}}"], {
        encoding: "utf8",
      }),
    ),
) {
  const { data: release } = await retry(() => github.rest.repos.getLatestRelease(upstream));
  requireValue(
    !release.draft && !release.prerelease && coreTag.test(release.tag_name),
    "Latest upstream release is not a stable Hindsight server release",
  );
  let { data: ref } = await github.rest.git.getRef({ ...upstream, ref: `tags/${release.tag_name}` });
  for (let depth = 0; ref.object.type === "tag" && depth < 5; depth++) {
    ({ data: ref } = await github.rest.git.getTag({ ...upstream, tag_sha: ref.object.sha }));
  }
  requireValue(ref.object.type === "commit", "Hindsight tag does not resolve to a commit");
  const version = release.tag_name.slice(1);
  const image = `ghcr.io/vectorize-io/hindsight:${version}`;
  return validatePin({ version, sha: ref.object.sha, image: `${image}@${await retry(() => inspect(image))}` });
}

async function resolve({ github, context, core, inspect }) {
  const config = readJson("compat/hindsight.json");
  const branch = context.payload.pull_request?.base.ref || context.ref.replace("refs/heads/", "");
  let pin;
  if (branch.startsWith("release/")) {
    requireValue(config.channel === "release", "Release branch must use frozen Hindsight inputs");
    pin = validatePin(config);
  } else {
    requireValue(config.channel === "latest", "Main must track the latest stable Hindsight release");
    pin = await latestHindsight(github, inspect);
  }
  for (const key of ["version", "sha", "image"]) core.setOutput(key, pin[key]);
  return pin;
}

function checkRule(rule, target, include, types, appId) {
  requireValue(rule.enforcement === "active" && rule.target === target, `${rule.name}: wrong target or disabled`);
  requireValue(
    isDeepStrictEqual(rule.conditions?.ref_name, { exclude: [], include: [include] }),
    `${rule.name}: unexpected ref targets`,
  );
  const bypass = appId ? [{ actor_id: appId, actor_type: "Integration", bypass_mode: "always" }] : [];
  if (Object.hasOwn(rule, "bypass_actors")) {
    requireValue(isDeepStrictEqual(rule.bypass_actors, bypass), `${rule.name}: unexpected bypass actors`);
  } else {
    let review;
    try { review = JSON.parse(process.env.RELEASE_SETTINGS_REVIEW || "null"); }
    catch { throw new ReleaseError("Invalid RELEASE_SETTINGS_REVIEW"); }
    const reviewedAt = review?.rulesets?.[rule.id];
    requireValue(
      review?.app_id === Number(process.env.RELEASE_APP_ID) && review.immutable_releases === true &&
        typeof rule.updated_at === "string" && typeof reviewedAt === "string" &&
        Date.parse(reviewedAt) === Date.parse(rule.updated_at),
      `${rule.name}: bypass actors are redacted; record the current owner-reviewed settings in RELEASE_SETTINGS_REVIEW`,
    );
  }
  const actual = new Set(rule.rules.map((item) => item.type));
  requireValue(
    types.every((type) => actual.has(type)),
    `${rule.name}: missing protection`,
  );
  if (appId) requireValue(actual.size === 1, `${rule.name}: creation bypass must not bypass other protections`);
}

async function checkRules(github, repository, appId) {
  requireValue(Number.isSafeInteger(appId) && appId > 0, "Set RELEASE_APP_ID to the dedicated App ID");
  const rules = await github.paginate(github.rest.repos.getRepoRulesets, { ...repository, per_page: 100 });
  const naming = rules.find((rule) => rule.name === "Enforce work branch names");
  requireValue(naming, "Work branch naming protection is missing");
  const { data: names } = await github.rest.repos.getRepoRuleset({ ...repository, ruleset_id: naming.id });
  requireValue(
    names.enforcement === "active" && names.conditions?.ref_name?.exclude?.includes("refs/heads/release/*"),
    "Exclude release/* from work branch creation restrictions; protect it with the dedicated release rulesets",
  );
  const specifications = [
    ["Release branch creation", "branch", "refs/heads/release/*", ["creation"], appId],
    [
      "Protect release branches",
      "branch",
      "refs/heads/release/*",
      ["non_fast_forward", "pull_request", "required_status_checks"],
      null,
    ],
    ["Release branch deletion", "branch", "refs/heads/release/*", ["deletion"], appId],
    ["Release tag creation", "tag", "refs/tags/v*", ["creation"], appId],
    ["Protect release tags", "tag", "refs/tags/v*", ["update", "deletion", "non_fast_forward"], null],
  ];
  for (const [name, target, include, types, bypass] of specifications) {
    const found = rules.find((rule) => rule.name === name);
    requireValue(found, `Configure the ${name} ruleset before releasing`);
    const { data } = await github.rest.repos.getRepoRuleset({ ...repository, ruleset_id: found.id });
    checkRule(data, target, include, types, bypass);
    if (name === "Protect release branches") {
      const template = readJson(".github/rulesets/protect-release-branches.json");
      requireValue(
        template.rules.every((expected) => data.rules.some((actual) => isDeepStrictEqual(actual, expected))),
        "Release branch protections must retain the reviewed checks, reviews, and scanning rules",
      );
    }
    if (target === "branch" && !bypass) {
      const pr = data.rules.find((rule) => rule.type === "pull_request").parameters;
      requireValue(
        pr.required_review_thread_resolution && JSON.stringify(pr.allowed_merge_methods) === '["squash"]',
        "Release branches require resolved reviews and squash merges",
      );
      const checks = data.rules.find((rule) => rule.type === "required_status_checks").parameters;
      const required = ["quality / checks", "aislop / aislop status", "codeql / analyze"];
      required.push(repository.repo === "hindsight-memory-router" ? "guard / guard" : "guard");
      if (repository.repo === "hindsight-memory-router") required.push("quality / container");
      else required.push("branch-policy / branch name");
      requireValue(
        checks.strict_required_status_checks_policy &&
          checks.do_not_enforce_on_create &&
          required.every((name) =>
            checks.required_status_checks.some((check) => check.context === name && check.integration_id === 15368),
          ),
        "Release branches must require the existing GitHub Actions gates and allow initial creation",
      );
    }
  }
}

function releaseVersion(tags, branches) {
  const version = readJson("release-version.json").version;
  requireValue(releaseTag.test(`v${version}`), "Set a plain X.Y.Z in release-version.json");
  requireValue(
    !tags.some((tag) => tag.name === `v${version}`) && !branches.some((branch) => branch.name === `release/${version}`),
    "Version already reserved; resume that release or bump release-version.json through a main PR",
  );
  return version;
}

function integrationUpstreams() {
  if (!existsSync("UPSTREAM_VERSION")) return null;
  const fields = Object.fromEntries(readFileSync("UPSTREAM_VERSION", "utf8").trim().split("\n").map((line) => line.split("=")));
  const coding = readJson("integrations/coding-agents/UPSTREAM.json");
  const pins = {
    openclaw: { version: fields.upstream_version, sha: fields.upstream_commit, path: fields.upstream_path },
    coding_agents: { version: coding.version, sha: coding.commit, path: coding.path },
  };
  for (const pin of Object.values(pins)) {
    requireValue(coreTag.test(`v${pin.version}`) && commitSha.test(pin.sha), "Invalid integration upstream provenance");
  }
  requireValue(fields.upstream_repo === "vectorize-io/hindsight" && coding.source === "https://github.com/vectorize-io/hindsight", "Unexpected integration upstream repository");
  return pins;
}

async function releasedRouter(github, hindsight) {
  const repository = { owner: "mickey-kras", repo: "hindsight-memory-router" };
  const { data: release } = await github.rest.repos.getLatestRelease(repository);
  requireValue(release.immutable && !release.draft && !release.prerelease && releaseTag.test(release.tag_name), "Publish an immutable router release before releasing integrations");
  const { data: tag } = await github.rest.git.getRef({ ...repository, ref: `tags/${release.tag_name}` });
  requireValue(tag.object.type === "commit" && commitSha.test(tag.object.sha), "Invalid router release commit");
  const { data: file } = await github.rest.repos.getContent({ ...repository, path: "release.json", ref: tag.object.sha });
  requireValue(file.type === "file" && file.encoding === "base64", "Router release manifest is missing");
  const manifest = JSON.parse(Buffer.from(file.content, "base64").toString("utf8"));
  requireValue(manifest.schema === 2 && `v${manifest.version}` === release.tag_name && !manifest.packages.length, "Invalid router release manifest");
  requireValue(isDeepStrictEqual(manifest.hindsight, hindsight), "Release the router for the current Hindsight pin before releasing integrations");
  const assets = await github.paginate(github.rest.repos.listReleaseAssets, { ...repository, release_id: release.id, per_page: 100 });
  const asset = assets.find((item) => item.name === "image-digests.txt");
  requireValue(asset && imageDigest.test(asset.digest), "Router image digest asset is missing or unverifiable");
  const { data } = await github.rest.repos.getReleaseAsset({ ...repository, asset_id: asset.id, headers: { accept: "application/octet-stream" } });
  const bytes = Buffer.from(data);
  requireValue(`sha256:${createHash("sha256").update(bytes).digest("hex")}` === asset.digest, "Router release asset checksum differs");
  const images = Object.fromEntries(bytes.toString("utf8").trim().split("\n").map((line) => line.split("=")));
  requireValue(images.commit === tag.object.sha && images.version === manifest.version, "Router image does not match its release");
  const pin = { version: manifest.version, sha: tag.object.sha, image: images.ghcr, dockerhub_image: images.dockerhub };
  validateRouter(pin);
  return pin;
}

function validateRouter(pin) {
  requireValue(pin && releaseTag.test(`v${pin.version}`) && commitSha.test(pin.sha), "Invalid router release pin");
  const prefix = "ghcr.io/mickey-kras/hindsight-memory-router@";
  const dockerhub = "docker.io/mickeykrasilnikov/hindsight-memory-router@";
  requireValue(typeof pin.image === "string" && pin.image.startsWith(prefix) && imageDigest.test(pin.image.slice(prefix.length)), "Router must use the released GHCR digest");
  requireValue(pin.dockerhub_image === `${dockerhub}${pin.image.slice(prefix.length)}`, "Router registry digests differ");
}

async function checkPackageReuse(github, repository, packages) {
  if (!packages.length) return;
  const releases = await github.paginate(github.rest.repos.listReleases, { ...repository, per_page: 100 });
  for (const release of releases.filter((item) => !item.draft && !item.prerelease)) {
    const assets = await github.paginate(github.rest.repos.listReleaseAssets, { ...repository, release_id: release.id, per_page: 100 });
    for (const pkg of packages) {
      const asset = assets.find((item) => item.name === pkg.path.split("/").pop());
      requireValue(!asset || asset.digest === `sha256:${pkg.sha256}`, "Package version already published with different bytes; bump that package version");
    }
  }
}

function packageAssets() {
  if (!existsSync("UPSTREAM_VERSION")) return [];
  return ["package.json", "src/upstream/coding-agents/package.json"].map((path) => {
    const pkg = readJson(path);
    requireValue(releaseTag.test(`v${pkg.version}`), `Invalid downstream version: ${path}`);
    const filename = `${pkg.name.replace(/^@/, "").replace("/", "-")}-${pkg.version}.tgz`;
    requireValue(/^[a-z0-9.-]+\.tgz$/.test(filename), "Invalid package filename");
    const asset = `packages/${filename}`;
    return { name: pkg.name, path: asset, version: pkg.version, sha256: checksum(asset) };
  });
}

function uiPackageAssets() {
  if (!existsSync("ui/package.json")) return [];
  const pkg = readJson("ui/package.json");
  requireValue(releaseTag.test(`v${pkg.version}`), "Invalid UI package version");
  const filename = `${pkg.name.replace(/^@/, "").replace("/", "-")}-${pkg.version}.tgz`;
  requireValue(/^[a-z0-9.-]+\.tgz$/.test(filename), "Invalid UI package filename");
  return [filename, `${filename}.sigstore.json`];
}

async function prepare({ github, context, core, inspect }) {
  requireValue(
    context.eventName === "workflow_dispatch" && context.ref === "refs/heads/main",
    "Release preparation is allowed only from the main workflow button",
  );
  const repository = context.repo;
  await checkRules(github, repository, Number(process.env.RELEASE_APP_ID));
  const { data: main } = await github.rest.git.getRef({ ...repository, ref: "heads/main" });
  requireValue(main.object.sha === context.sha, "Main advanced during validation; run preparation again");
  const branches = await github.paginate(github.rest.repos.listBranches, { ...repository, per_page: 100 });
  for (const branch of branches.filter((item) => item.name.startsWith("release/"))) {
    const existing = await optional(() =>
      github.rest.repos.getContent({ ...repository, path: "release.json", ref: branch.name }),
    );
    if (existing?.encoding === "base64") {
      const previous = JSON.parse(Buffer.from(existing.content, "base64").toString("utf8"));
      if (previous.preparation_run === context.runId && previous.base === context.sha) {
        await core.summary.addRaw(`Already prepared: ${branch.name}. Rerun its release workflow if needed.\n`).write();
        return;
      }
    }
  }
  const pin = await latestHindsight(github, inspect);
  const tags = await github.paginate(github.rest.repos.listTags, { ...repository, per_page: 100 });
  const version = releaseVersion(tags, branches);
  const packages = packageAssets();
  const manifest = { schema: 2, version, base: context.sha, preparation_run: context.runId, hindsight: pin, packages };
  if (packages.length) {
    await checkPackageReuse(github, repository, packages);
    manifest.router = await releasedRouter(github, pin);
    manifest.integration_upstreams = integrationUpstreams();
    const { data: nix } = await github.rest.repos.getCommit({ owner: "openclaw", repo: "nix-openclaw", ref: "main" });
    requireValue(commitSha.test(nix.sha), "Invalid nix-openclaw commit");
    manifest.nix_openclaw = nix.sha;
  }
  const tree = [
    { path: "release.json", mode: "100644", type: "blob", content: json(manifest) },
    { path: "compat/hindsight.json", mode: "100644", type: "blob", content: json({ channel: "release", ...pin }) },
  ];
  if (!packages.length) {
    requireValue(readFileSync("pyproject.toml", "utf8").includes(`version = "${version}"`), "Align pyproject.toml with release-version.json before preparing");
  }
  const { data: base } = await github.rest.git.getCommit({ ...repository, commit_sha: context.sha });
  const { data: createdTree } = await github.rest.git.createTree({ ...repository, base_tree: base.tree.sha, tree });
  const { data: commit } = await github.rest.git.createCommit({
    ...repository,
    message: `Prepare v${version}`,
    tree: createdTree.sha,
    parents: [context.sha],
  });
  const { data: currentMain } = await github.rest.git.getRef({ ...repository, ref: "heads/main" });
  requireValue(currentMain.object.sha === context.sha, "Main advanced while freezing inputs; run preparation again");
  await github.rest.git.createRef({ ...repository, ref: `refs/heads/release/${version}`, sha: commit.sha });
  await core.summary
    .addRaw(`Release branch: release/${version}\nMain snapshot: ${context.sha}\nHindsight: ${pin.version}\nCommit: ${commit.sha}\n`)
    .write();
}

async function validate({ github, context, core }) {
  requireValue(
    context.eventName === "push" && context.workflow === "release",
    "Publication is allowed only through the release workflow",
  );
  const manifest = readJson("release.json");
  requireValue(manifest.schema === 2 && releaseTag.test(`v${manifest.version}`), "Invalid release manifest");
  requireValue(context.ref === `refs/heads/release/${manifest.version}`, "Release branch does not match the manifest");
  requireValue(commitSha.test(manifest.base), "Invalid preparation base");
  requireValue(readJson("release-version.json").version === manifest.version, "Repository version differs from the release");
  requireValue(
    Array.isArray(manifest.packages) &&
      manifest.packages.length === (context.repo.repo === "hindsight-memory-router-integrations" ? 2 : 0),
    "Invalid release package inventory",
  );
  validatePin(manifest.hindsight);
  requireValue(
    isDeepStrictEqual(readJson("compat/hindsight.json"), { channel: "release", ...manifest.hindsight }),
    "Release Hindsight inputs changed",
  );
  await checkRules(github, context.repo, Number(process.env.RELEASE_APP_ID));
  const { data: comparison } = await github.rest.repos.compareCommitsWithBasehead({
    ...context.repo,
    basehead: `${manifest.base}...${context.sha}`,
  });
  requireValue(
    comparison.status === "ahead" &&
      comparison.total_commits <= 250 &&
      comparison.commits.length === comparison.total_commits,
    "Release must descend from its prepared main commit",
  );
  requireValue(
    comparison.files && comparison.files.length < 300,
    "Release diff is missing or too large to validate safely",
  );
  requireValue(
    !comparison.files.some((file) =>
      [file.filename, file.previous_filename || ""].some((path) => path.startsWith(".github/")),
    ),
    "Release automation must remain identical to its main baseline",
  );
  const { data: original } = await github.rest.repos.getContent({
    ...context.repo,
    path: "release.json",
    ref: comparison.commits[0].sha,
  });
  requireValue(original.type === "file" && original.encoding === "base64", "Preparation manifest is missing");
  const prepared = JSON.parse(Buffer.from(original.content, "base64").toString("utf8"));
  const frozen = ({ packages: _packages, ...fields }) => fields;
  requireValue(isDeepStrictEqual(frozen(prepared), frozen(manifest)), "Prepared release inputs are immutable");
  const { data: main } = await github.rest.repos.compareCommitsWithBasehead({
    ...context.repo,
    basehead: `${manifest.base}...main`,
  });
  requireValue(["ahead", "identical"].includes(main.status), "Preparation base is not on main");
  const { data: branch } = await github.rest.git.getRef({ ...context.repo, ref: `heads/release/${manifest.version}` });
  requireValue(branch.object.sha === context.sha, "Release branch advanced; wait for its new validation run");
  requireValue(
    JSON.stringify(packageAssets()) === JSON.stringify(manifest.packages),
    "Refresh release.json package hashes and versions with the tested package changes",
  );
  if (manifest.packages.length) {
    validateRouter(manifest.router);
    requireValue(commitSha.test(manifest.nix_openclaw), "Invalid nix-openclaw pin");
    requireValue(isDeepStrictEqual(integrationUpstreams(), manifest.integration_upstreams), "Integration upstream provenance changed");
    await checkPackageReuse(github, context.repo, manifest.packages);
  } else {
    requireValue(readFileSync("pyproject.toml", "utf8").includes(`version = "${manifest.version}"`), "Python distribution version differs from the release");
  }
  const tag = await optional(() => github.rest.git.getRef({ ...context.repo, ref: `tags/v${manifest.version}` }));
  requireValue(
    !tag || (tag.object.type === "commit" && tag.object.sha === context.sha),
    "Release tag already belongs to another commit",
  );
  core.setOutput("version", manifest.version);
  return manifest;
}

function shouldPromote(version, releases) {
  const semver = require("semver");
  requireValue(releaseTag.test(`v${version}`), "Invalid release version");
  return !releases.some((release) => releaseTag.test(release.tag_name) && !release.draft && !release.prerelease && semver.gt(release.tag_name.slice(1), version));
}

function releaseNotes(manifest, sha) {
  const rows = manifest.packages.length
    ? [`| Router | ${manifest.router.version} |`, ...manifest.packages.map((pkg) => `| ${pkg.name} | ${pkg.version} |`)]
    : [`| Router | ${manifest.version} |`];
  return `| Component | Version |\n| --- | --- |\n${rows.join("\n")}\n\nHindsight: ${manifest.hindsight.version}.\nCommit: ${sha}.\n\nSee release.json for exact upstream commits, package checksums and${manifest.packages.length ? " the tested router image digest" : " image-digests.txt for published images"}.`;
}

async function finalize({ github, context, core }) {
  const manifest = await validate({ github, context, core });
  const tag = `v${manifest.version}`;
  const existing = await optional(() => github.rest.git.getRef({ ...context.repo, ref: `tags/${tag}` }));
  if (!existing) await github.rest.git.createRef({ ...context.repo, ref: `refs/tags/${tag}`, sha: context.sha });
  let release = await optional(() => github.rest.repos.getReleaseByTag({ ...context.repo, tag }));
  if (!release) {
    ({ data: release } = await github.rest.repos.createRelease({
      ...context.repo,
      tag_name: tag,
      target_commitish: context.sha,
      name: tag,
      draft: true,
      prerelease: false,
      body: releaseNotes(manifest, context.sha),
    }));
  }
  const paths = [
    "release.json",
    ...manifest.packages.map((pkg) => pkg.path),
    ...(manifest.packages.length ? ["PACKAGE_SHA256", "PACKAGE_NIX_HASHES"] : ["image-digests.txt", "sbom.cdx.json", ...uiPackageAssets()]),
  ];
  const assets = await github.paginate(github.rest.repos.listReleaseAssets, {
    ...context.repo,
    release_id: release.id,
    per_page: 100,
  });
  for (const path of paths) {
    const name = path.split("/").pop();
    const asset = assets.find((item) => item.name === name);
    if (asset) {
      requireValue(asset.digest === `sha256:${checksum(path)}`, `Existing release asset differs: ${name}`);
    } else {
      requireValue(release.draft, `Published release is missing ${name}`);
      await github.rest.repos.uploadReleaseAsset({
        ...context.repo,
        release_id: release.id,
        name,
        data: readFileSync(path),
        headers: { "content-type": "application/octet-stream" },
      });
    }
  }
  const releases = await github.paginate(github.rest.repos.listReleases, { ...context.repo, per_page: 100 });
  const latest = shouldPromote(manifest.version, releases);
  if (release.draft || latest) {
    await github.rest.repos.updateRelease({
      ...context.repo,
      release_id: release.id,
      draft: false,
      prerelease: false,
      make_latest: latest ? "true" : "false",
    });
  }
  core.setOutput("latest", String(latest));
}

function publishedVersion(context) {
  requireValue(
    context.eventName === "push" && context.workflow === "release" &&
      context.ref.startsWith("refs/heads/release/"),
    "Release follow-up is allowed only through the release workflow",
  );
  const version = context.ref.slice("refs/heads/release/".length);
  requireValue(releaseTag.test(`v${version}`), "Invalid release branch version");
  requireValue(commitSha.test(context.sha), "Invalid release commit");
  return version;
}

function nextPatch(version) {
  requireValue(releaseTag.test(`v${version}`), "Invalid released version");
  const [major, minor, patch] = version.split(".").map(Number);
  return `${major}.${minor}.${patch + 1}`;
}

async function publishedTag(github, repository, version, sha) {
  const tag = await optional(() => github.rest.git.getRef({ ...repository, ref: `tags/v${version}` }));
  requireValue(
    tag && tag.object.type === "commit" && tag.object.sha === sha,
    `Refusing follow-up: v${version} is not published at this commit`,
  );
}

function mergeVersionBump({ repository, number, sha }) {
  execFileSync("gh", ["pr", "merge", String(number), "--repo", repository,
    "--auto", "--squash", "--match-head-commit", sha], { timeout: 30000, stdio: "pipe" });
}

async function queueVersionBump({ github, repository, number, branch, version, next, merge }) {
  const params = { ...repository, pull_number: number };
  const { data: pull } = await github.rest.pulls.get(params);
  const fullName = `${repository.owner}/${repository.repo}`;
  requireValue(pull.state === "open" && !pull.draft && pull.base.ref === "main" &&
    pull.head.repo?.full_name === fullName && pull.head.ref === branch && commitSha.test(pull.head.sha),
  `Refusing auto-merge: #${number} is not the expected bump PR`);
  // On retries, a maintainer may have edited the generated PR. Only the exact
  // two version-line replacements are eligible for unattended merging.
  const expected = {
    "release-version.json": [`-  "version": "${version}"`, `+  "version": "${next}"`],
    "pyproject.toml": [`-version = "${version}"`, `+version = "${next}"`],
  };
  const files = await github.paginate(github.rest.pulls.listFiles, { ...params, per_page: 100 });
  requireValue(files.length === 2 && new Set(files.map(file => file.filename)).size === 2 &&
    files.every(file => file.status === "modified" && file.additions === 1 && file.deletions === 1 &&
      expected[file.filename] && isDeepStrictEqual(
        (file.patch || "").split("\n").filter(line => /^[+-]/.test(line)), expected[file.filename])),
  `Refusing auto-merge: #${number} contains changes beyond the next patch version`);
  if (pull.auto_merge) {
    requireValue(pull.auto_merge.merge_method === "squash", `#${number} must use squash auto-merge`);
    return;
  }
  // gh queues pending checks or merges an already-green retry; branch rules apply.
  await merge({ repository: fullName, number, sha: pull.head.sha });
}

async function bumpReleasedVersion({ github, context, core, merge = mergeVersionBump }) {
  const version = publishedVersion(context);
  await publishedTag(github, context.repo, version, context.sha);
  const next = nextPatch(version);
  const repository = context.repo;
  const branch = `ci/bump-release-version-${next.replaceAll(".", "-")}`;
  const summary = core.summary.addHeading("Release follow-up: version bump", 3);
  const open = await github.paginate(github.rest.pulls.list, {
    ...repository,
    state: "open",
    head: `${repository.owner}:${branch}`,
    per_page: 100,
  });
  if (open.length) {
    await queueVersionBump({ github, repository, number: open[0].number, branch, version, next, merge });
    await summary.addRaw(`Reused #${open[0].number}; squash auto-merge enabled.\n`).write();
    return;
  }
  const { data: main } = await github.rest.git.getRef({ ...repository, ref: "heads/main" });
  const read = async (path) => {
    const { data: file } = await github.rest.repos.getContent({ ...repository, path, ref: main.object.sha });
    requireValue(file.type === "file" && file.encoding === "base64", `Cannot read ${path} on main`);
    return Buffer.from(file.content, "base64").toString("utf8");
  };
  const current = JSON.parse(await read("release-version.json")).version;
  if (current !== version) {
    await summary.addRaw(`Main already targets ${current}; no bump needed.\n`).write();
    return;
  }
  const pyproject = await read("pyproject.toml");
  requireValue(
    pyproject.split(`version = "${version}"`).length === 2,
    `pyproject.toml on main must pin version = "${version}" exactly once`,
  );
  const { data: base } = await github.rest.git.getCommit({ ...repository, commit_sha: main.object.sha });
  const { data: tree } = await github.rest.git.createTree({
    ...repository,
    base_tree: base.tree.sha,
    tree: [
      { path: "release-version.json", mode: "100644", type: "blob", content: json({ version: next }) },
      { path: "pyproject.toml", mode: "100644", type: "blob", content: pyproject.replace(`version = "${version}"`, `version = "${next}"`) },
    ],
  });
  const { data: commit } = await github.rest.git.createCommit({
    ...repository,
    message: `Bump release version to ${next}`,
    tree: tree.sha,
    parents: [main.object.sha],
  });
  const ref = `heads/${branch}`;
  if (await optional(() => github.rest.git.getRef({ ...repository, ref }))) {
    await github.rest.git.deleteRef({ ...repository, ref });
  }
  await github.rest.git.createRef({ ...repository, ref: `refs/${ref}`, sha: commit.sha });
  const { data: pr } = await github.rest.pulls.create({
    ...repository,
    title: `Bump release version to ${next}`,
    head: branch,
    base: "main",
    body: `Release v${version} is published; reserve the next version on main.\n\n- Bump release-version.json and pyproject.toml to ${next}\n- Squash-merges automatically after required checks pass\n`,
    maintainer_can_modify: false,
  });
  await queueVersionBump({ github, repository, number: pr.number, branch, version, next, merge });
  await summary.addRaw(`Opened #${pr.number}: bump ${version} to ${next}; squash auto-merge enabled.\n`).write();
}

async function deletePublishedBranch({ github, context, core }) {
  const version = publishedVersion(context);
  await publishedTag(github, context.repo, version, context.sha);
  const summary = core.summary.addHeading("Release follow-up: release branch", 3);
  const ref = `heads/release/${version}`;
  const current = await optional(() => github.rest.git.getRef({ ...context.repo, ref }));
  if (!current) {
    await summary.addRaw(`Branch \`release/${version}\` is already absent.\n`);
  } else {
    requireValue(
      current.object.sha === context.sha,
      `Refusing to delete release/${version}: the branch advanced past the published commit`,
    );
    await github.rest.git.deleteRef({ ...context.repo, ref });
    await summary.addRaw(`Deleted \`release/${version}\`.\n`);
  }
  const branches = await github.paginate(github.rest.repos.listBranches, { ...context.repo, per_page: 100 });
  for (const item of branches) {
    if (!item.name.startsWith("release/") || item.name === `release/${version}`) continue;
    const stale = item.name.slice("release/".length);
    if (!releaseTag.test(`v${stale}`)) continue;
    try {
      const tag = await optional(() => github.rest.git.getRef({ ...context.repo, ref: `tags/v${stale}` }));
      if (!tag || tag.object.type !== "commit") continue;
      if (item.commit.sha !== tag.object.sha) {
        core.warning(`Kept ${item.name}: the branch advanced past its published tag`);
        await summary.addRaw(`Kept \`${item.name}\`: the branch advanced past its published tag.\n`);
        continue;
      }
      await github.rest.git.deleteRef({ ...context.repo, ref: `heads/${item.name}` });
      await summary.addRaw(`Pruned \`${item.name}\`: v${stale} is published at the same commit.\n`);
    } catch (error) {
      if (error.status === 404) continue;
      core.error(`Pruning ${item.name} failed: ${error.message}`);
      await summary.addRaw(`Pruning \`${item.name}\` failed (${error.message}); delete it manually.\n`);
    }
  }
  await summary.write();
}

module.exports = {
  ReleaseError,
  retry,
  validatePin,
  latestHindsight,
  resolve,
  checkRule,
  releaseVersion,
  integrationUpstreams,
  releasedRouter,
  validateRouter,
  checkPackageReuse,
  shouldPromote,
  prepare,
  validate,
  finalize,
  publishedVersion,
  nextPatch,
  bumpReleasedVersion,
  deletePublishedBranch,
  checkRules,
  packageAssets,
  uiPackageAssets,
};
