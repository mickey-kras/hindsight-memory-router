const test = require("node:test");
const assert = require("node:assert/strict");
const { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const { createHash } = require("node:crypto");
const release = require("./release.cjs");
const { rulesets } = require("./release-settings.cjs");

const base = "a".repeat(40);
const sha = "b".repeat(40);
const digest = `sha256:${"c".repeat(64)}`;
const pin = { version: "0.9.2", sha: base, image: `ghcr.io/vectorize-io/hindsight:0.9.2@${digest}` };
const templateData = JSON.parse(readFileSync(".github/rulesets/protect-release-branches.json", "utf8"));
const fixtureChecks = templateData.rules.find((rule) => rule.type === "required_status_checks").parameters
  .required_status_checks;
for (const context of ["quality / container", "guard / guard", "guard", "branch-policy / branch name"]) {
  if (!fixtureChecks.some((check) => check.context === context)) fixtureChecks.push({ context, integration_id: 15368 });
}
const template = JSON.stringify(templateData);
const encode = (value) => ({
  type: "file",
  encoding: "base64",
  content: Buffer.from(`${JSON.stringify(value, null, 2)}\n`).toString("base64"),
});
const notFound = () => {
  throw Object.assign(new Error("Not found"), { status: 404 });
};
const put = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);

async function fixture(fn) {
  const before = process.cwd();
  const previousId = process.env.RELEASE_APP_ID;
  const directory = mkdtempSync(join(tmpdir(), "release-test-"));
  process.chdir(directory);
  process.env.RELEASE_APP_ID = "123";
  mkdirSync(".github/rulesets", { recursive: true });
  mkdirSync("compat");
  writeFileSync(".github/rulesets/protect-release-branches.json", template);
  put("compat/hindsight.json", { channel: "latest" });
  put("release-version.json", { version: "0.1.0" });
  writeFileSync("pyproject.toml", '[project]\nversion = "0.1.0"\n');
  try {
    await fn();
  } finally {
    process.chdir(before);
    if (previousId === undefined) delete process.env.RELEASE_APP_ID;
    else process.env.RELEASE_APP_ID = previousId;
    rmSync(directory, { recursive: true, force: true });
  }
}

function mock() {
  const state = {
    refs: { "heads/main": { object: { type: "commit", sha: base } } },
    rules: rulesets(123),
    tags: [],
    branches: [],
    calls: [],
    assets: [],
    releases: [],
    warnings: [],
    errors: [],
    comparison: { status: "ahead", total_commits: 1, commits: [{ sha }], files: [{ filename: "release.json" }] },
  };
  state.rules.push({
    name: "Enforce work branch names",
    enforcement: "active",
    conditions: { ref_name: { exclude: ["refs/heads/release/*"] } },
  });
  state.rules.forEach((rule, index) => {
    rule.id = index + 1;
  });
  const data = (value) => ({ data: value });
  const github = {
    rest: {
      repos: {
        getRepoRulesets: () => data(state.rules),
        getRepoRuleset: ({ ruleset_id }) => data(state.rules.find((rule) => rule.id === ruleset_id)),
        getLatestRelease: () => data({ tag_name: "v0.9.2", draft: false, prerelease: false }),
        listTags: () => data(state.tags),
        listBranches: () => data(state.branches),
        getCommit: () => data({ sha: base }),
        getContent: ({ path }) => {
          if (path === "compat/hindsight.json") return data(encode({ channel: "release", ...pin }));
          if (path === "release-version.json") return data(encode({ version: "0.1.0" }));
          if (path === "pyproject.toml") return data({ type: "file", encoding: "base64", content: Buffer.from('version = "0.1.0"').toString("base64") });
          return data(encode(state.prepared));
        },
        compareCommitsWithBasehead: ({ basehead }) =>
          data(basehead.endsWith("...main") ? { status: "identical" } : state.comparison),
        getReleaseByTag: ({ tag }) => {
          const found = state.releasesByTag?.[tag] || state.release;
          return found ? data(found) : notFound();
        },
        createRelease: (args) => {
          state.calls.push("draft");
          state.release = { id: 1, ...args };
          return data(state.release);
        },
        listReleaseAssets: () => data(state.assets),
        uploadReleaseAsset: (args) => {
          state.calls.push(`asset:${args.name}`);
          if (state.failUpload) throw new Error("upload failed");
          state.assets.push({
            name: args.name,
            digest: `sha256:${createHash("sha256").update(args.data).digest("hex")}`,
          });
          return data({});
        },
        listReleases: () => data(state.releases),
        updateRelease: (args) => {
          state.calls.push("publish");
          Object.assign(state.release, args);
          return data(state.release);
        },
      },
      git: {
        getRef: ({ repo, ref }) =>
          repo === "hindsight"
            ? data({ object: { type: "commit", sha: base } })
            : state.refs[ref]
              ? data(state.refs[ref])
              : notFound(),
        getCommit: () => data({ tree: { sha: base } }),
        createTree: (args) => {
          state.calls.push("tree");
          state.tree = args.tree;
          return data({ sha });
        },
        createCommit: () => {
          state.calls.push("commit");
          return data({ sha });
        },
        createRef: ({ ref, sha: commit }) => {
          state.calls.push(ref);
          assert.equal(state.refs[ref.replace(/^refs\//, "")], undefined);
          state.refs[ref.replace(/^refs\//, "")] = { object: { type: "commit", sha: commit } };
          return data({});
        },
        deleteRef: ({ ref }) => {
          state.calls.push(`delete:${ref}`);
          if (!state.refs[ref]) throw Object.assign(new Error("Not found"), { status: 404 });
          delete state.refs[ref];
          return data({});
        },
      },
      actions: {
        listWorkflowRuns: () => data(state.runs || []),
        getWorkflowRun: ({ run_id }) => data((state.runs || []).find(run => run.id === run_id)),
        listWorkflowRunArtifacts: () => data(state.artifacts || []),
        reRunWorkflow: ({ run_id }) => { state.calls.push(`rerun:${run_id}`); return data({}); },
        reRunWorkflowFailedJobs: ({ run_id }) => { state.calls.push(`rerun-failed:${run_id}`); return data({}); },
      },
      pulls: {
        list: () => data(state.pulls || []),
        get: () => data(state.pull),
        listFiles: () => data(state.bumpFiles || [
          { filename: "release-version.json", status: "modified", additions: 1, deletions: 1,
            patch: '@@ -1,3 +1,3 @@\n {\n-  "version": "0.1.0"\n+  "version": "0.1.1"\n }' },
          { filename: "pyproject.toml", status: "modified", additions: 1, deletions: 1,
            patch: '@@ -1,2 +1,2 @@\n [project]\n-version = "0.1.0"\n+version = "0.1.1"' },
        ]),
        create: (args) => {
          state.calls.push(`pr:${args.head}`);
          state.pull = { number: 7, ...args, state: "open", draft: false,
            base: { ref: args.base },
            head: { ref: args.head, sha, repo: { full_name: "example/hindsight-memory-router" } } };
          state.pulls = [state.pull];
          return data(state.pull);
        },
      },
    },
    paginate: async (method, args) => (await method(args)).data,
  };
  const outputs = {};
  const summary = {
    addRaw: (value) => { state.summary = (state.summary || "") + value; return summary; },
    addHeading: () => summary,
    write: async () => {},
  };
  const core = {
    setOutput: (key, value) => {
      outputs[key] = value;
    },
    warning: (line) => state.warnings.push(line),
    error: (line) => state.errors.push(line),
    summary,
  };
  const context = {
    repo: { owner: "example", repo: "hindsight-memory-router" },
    eventName: "workflow_dispatch",
    workflow: "release",
    ref: "refs/heads/main",
    sha: base,
    runId: 5,
    payload: {},
  };
  const merge = async (args) => {
    state.calls.push(`merge:${args.number}`);
    state.merge = args;
    if (state.failMerge) throw new Error("auto-merge unavailable");
  };
  return { github, state, context, core, outputs, inspect: () => digest, merge };
}

function prepared(m) {
  const manifest = { schema: 2, version: "0.1.0", base, preparation_run: 5, hindsight: pin, packages: [] };
  m.state.prepared = structuredClone(manifest);
  m.context.ref = "refs/heads/release/0.1.0";
  m.context.sha = sha;
  m.context.eventName = "push";
  m.context.workflow = "release";
  m.state.refs["heads/release/0.1.0"] = { object: { type: "commit", sha } };
  put("release.json", manifest);
  put("compat/hindsight.json", { channel: "release", ...pin });
  writeFileSync("pyproject.toml", '[project]\nversion = "0.1.0"\n');
  writeFileSync("image-digests.txt", `ghcr=${digest}\ndockerhub=${digest}\n`);
  writeFileSync("sbom.cdx.json", '{"bomFormat":"CycloneDX"}\n');
  mkdirSync("ui", { recursive: true });
  put("ui/package.json", { name: "memory-router-ui", version: "0.2.0" });
  writeFileSync("memory-router-ui-0.2.0.tgz", "tgz\n");
  writeFileSync("memory-router-ui-0.2.0.tgz.sigstore.json", "{}\n");
  return manifest;
}

test("pins reject floating tags, mismatched versions, malformed SHAs and injected input", () => {
  assert.deepEqual(release.validatePin(pin), pin);
  for (const bad of [
    { image: "ghcr.io/vectorize-io/hindsight:latest" },
    { version: "01.9.2" },
    { sha: "main" },
    { image: pin.image.replace(":0.9.2@", ":0.9.1@") },
    { version: "0.9.2\nmalicious" },
  ]) {
    assert.throws(() => release.validatePin({ ...pin, ...bad }));
  }
});

test("latest resolves versioned image and peels annotated upstream tags", async () => {
  const m = mock();
  m.github.rest.git.getRef = async () => ({ data: { object: { type: "tag", sha } } });
  m.github.rest.git.getTag = async () => ({ data: { object: { type: "commit", sha: base } } });
  assert.deepEqual(
    await release.latestHindsight(m.github, (image) => {
      assert.equal(image, "ghcr.io/vectorize-io/hindsight:0.9.2");
      return digest;
    }),
    pin,
  );
  m.github.rest.repos.getLatestRelease = () => ({ data: { tag_name: "openclaw-v0.12.0" } });
  await assert.rejects(release.latestHindsight(m.github, m.inspect), /stable Hindsight/);
});

test("main and release PRs resolve consistently; release never queries moving upstream", () =>
  fixture(async () => {
    const m = mock();
    assert.deepEqual(await release.resolve(m), pin);
    assert.equal(m.outputs.image, pin.image);
    put("compat/hindsight.json", { channel: "release", ...pin });
    m.context.payload.pull_request = { base: { ref: "release/0.1.0" } };
    m.github.rest.repos.getLatestRelease = () => {
      throw new Error("must not query latest");
    };
    assert.deepEqual(await release.resolve(m), { channel: "release", ...pin });
    put("compat/hindsight.json", { channel: "latest" });
    await assert.rejects(release.resolve(m), /frozen/);
  }));

test("reviewed versions are independent of upstream and cannot reuse reserved branches or tags", () =>
  fixture(async () => {
    assert.equal(release.releaseVersion([], []), "0.1.0");
    assert.throws(() => release.releaseVersion([{ name: "v0.1.0" }], []), /reserved/);
    assert.throws(() => release.releaseVersion([], [{ name: "release/0.1.0" }]), /reserved/);
    for (const version of ["0.1.0-router.1", "0.1.0+build.1", "01.1.0", "main", "0.1.0\n"]) {
      put("release-version.json", { version });
      assert.throws(() => release.releaseVersion([], []), /plain/);
    }
  }));

test("latest follows component release versions, ignoring older releases and drafts", () => {
  assert.equal(release.shouldPromote("0.1.10", [{ tag_name: "v0.1.9" }]), true);
  assert.equal(release.shouldPromote("0.1.10", [{ tag_name: "v0.2.0" }]), false);
  assert.equal(release.shouldPromote("0.1.0", [{ tag_name: "v0.2.0", draft: true }]), true);
  assert.equal(release.shouldPromote("0.1.0", [{ tag_name: "v0.2.0", prerelease: true }]), true);
});

test("rules require creation-only App bypass and retain branch/tag protection", () =>
  fixture(async () => {
    const m = mock();
    // Object key order in GitHub responses is immaterial.
    m.state.rules[0].bypass_actors = [{ bypass_mode: "always", actor_type: "Integration", actor_id: 123 }];
    await release.checkRules(m.github, m.context.repo, 123);
    m.state.rules[1].bypass_actors = [{ actor_id: 123, actor_type: "Integration", bypass_mode: "always" }];
    await assert.rejects(release.checkRules(m.github, m.context.repo, 123), /bypass/);
    m.state.rules[1].bypass_actors = [];
    m.state.rules.find((rule) => rule.name === "Protect release tags").rules = [{ type: "deletion" }];
    await assert.rejects(release.checkRules(m.github, m.context.repo, 123), /protection/);
  }));

test("disabled naming exception and reduced scanning protections fail closed", () =>
  fixture(async () => {
    const m = mock();
    m.state.rules.at(-1).conditions.ref_name.exclude = [];
    await assert.rejects(release.checkRules(m.github, m.context.repo, 123), /Exclude/);
    m.state.rules.at(-1).conditions.ref_name.exclude = ["refs/heads/release/*"];
    m.state.rules[1].rules = m.state.rules[1].rules.filter((rule) => rule.type !== "code_scanning");
    await assert.rejects(release.checkRules(m.github, m.context.repo, 123), /scanning/);
  }));

test("preparation freezes inputs and retains the reviewed independent version", () =>
  fixture(async () => {
    const m = mock();
    await release.prepare(m);
    assert.deepEqual(m.state.calls, ["tree", "commit", "refs/heads/release/0.1.0"]);
    const files = Object.fromEntries(m.state.tree.map((item) => [item.path, item.content]));
    assert.deepEqual(JSON.parse(files["compat/hindsight.json"]), { channel: "release", ...pin });
    assert.equal(files["pyproject.toml"], undefined);
    assert.equal(JSON.parse(files["release.json"]).version, "0.1.0");
    m.state.prepared = JSON.parse(files["release.json"]);
    m.state.branches = [{ name: "release/0.1.0" }];
    await release.prepare(m);
    assert.equal(m.state.calls.length, 3, "rerunning preparation must not create another branch");
  }));

test("preparation rejects non-main dispatches and a main branch that advanced during checks", () =>
  fixture(async () => {
    const m = mock();
    m.context.ref = "refs/heads/ci/example";
    await assert.rejects(release.prepare(m), /only from main/);
    m.context.ref = "refs/heads/main";
    m.context.sha = sha;
    await assert.rejects(release.prepare(m), /Main advanced/);
    assert.equal(m.state.calls.length, 0);
  }));

test("release validation rejects changed pins, workflow changes, stale heads and moved tags", () =>
  fixture(async () => {
    const m = mock();
    const manifest = prepared(m);
    await release.validate(m);
    const changed = { ...manifest, hindsight: { ...pin, sha } };
    put("release.json", changed);
    put("compat/hindsight.json", { channel: "release", ...changed.hindsight });
    await assert.rejects(release.validate(m), /immutable/);
    prepared(m);
    m.state.comparison.files.push({ filename: ".github/workflows/release.yml" });
    await assert.rejects(release.validate(m), /automation/);
    m.state.comparison.files.pop();
    m.state.refs["heads/release/0.1.0"].object.sha = base;
    await assert.rejects(release.validate(m), /advanced/);
    prepared(m);
    m.state.refs["tags/v0.1.0"] = { object: { type: "commit", sha: base } };
    await assert.rejects(release.validate(m), /another commit/);
  }));

test("finalization publishes only after uploading assets and never moves or recreates its tag", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    await release.finalize(m);
    assert.deepEqual(m.state.calls, [
      "refs/tags/v0.1.0",
      "draft",
      "asset:release.json",
      "asset:image-digests.txt",
      "asset:sbom.cdx.json",
      "asset:memory-router-ui-0.2.0.tgz",
      "asset:memory-router-ui-0.2.0.tgz.sigstore.json",
      "publish",
    ]);
    assert.equal(m.outputs.latest, "true");
    await release.finalize(m);
    assert.equal(m.state.calls.filter((call) => call.startsWith("refs/tags/")).length, 1);
    m.state.assets[0].digest = `sha256:${"f".repeat(64)}`;
    await assert.rejects(release.finalize(m), /Existing release asset differs/);
  }));

test("partial release upload remains a draft and can be resumed without changing its tag", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    m.state.failUpload = true;
    await assert.rejects(release.finalize(m), /upload failed/);
    assert.equal(m.state.release.draft, true);
    assert.equal(m.state.calls.includes("publish"), false);
    m.state.failUpload = false;
    await release.finalize(m);
    assert.equal(m.state.release.draft, false);
    assert.equal(m.state.calls.filter((call) => call.startsWith("refs/tags/")).length, 1);
  }));

test("publication rejects dispatch through another workflow", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    m.context.eventName = "workflow_dispatch";
    m.context.workflow = "main";
    await assert.rejects(release.finalize(m), /only from main/);
    assert.deepEqual(m.state.calls, []);
  }));

test("integration package fixes can update tested assets while upstream pins remain frozen", () =>
  fixture(async () => {
    const m = mock();
    const manifest = prepared(m);
    m.context.repo.repo = "hindsight-memory-router-integrations";
    writeFileSync("UPSTREAM_VERSION", `upstream_repo=vectorize-io/hindsight\nupstream_version=0.11.1\nupstream_commit=${base}\nupstream_path=hindsight-integrations/openclaw\n`);
    mkdirSync("integrations/coding-agents", { recursive: true });
    put("integrations/coding-agents/UPSTREAM.json", { source: "https://github.com/vectorize-io/hindsight", version: "0.5.1", commit: base, path: "hindsight-integrations/coding-agents" });
    mkdirSync("src/upstream/coding-agents", { recursive: true });
    mkdirSync("packages");
    put("package.json", { name: "@example/openclaw", version: "0.12.0" });
    put("src/upstream/coding-agents/package.json", { name: "@example/coding-agents", version: "0.6.0" });
    writeFileSync("packages/example-openclaw-0.12.0.tgz", "original test fixture");
    writeFileSync("packages/example-coding-agents-0.6.0.tgz", "coding test fixture");
    manifest.packages = release.packageAssets();
    manifest.nix_openclaw = base;
    manifest.router = { version: "0.1.0", sha: base, image: `ghcr.io/mickey-kras/hindsight-memory-router@${digest}`, dockerhub_image: `docker.io/mickeykrasilnikov/hindsight-memory-router@${digest}` };
    manifest.integration_upstreams = release.integrationUpstreams();
    m.state.prepared = structuredClone(manifest);
    put("release.json", manifest);
    await release.validate(m);
    put("package.json", { name: "@example/openclaw", version: "0.12.1" });
    writeFileSync("packages/example-openclaw-0.12.1.tgz", "fixed test fixture");
    await assert.rejects(release.validate(m), /Refresh release.json/);
    manifest.packages = release.packageAssets();
    put("release.json", manifest);
    await release.validate(m);
    manifest.nix_openclaw = sha;
    put("release.json", manifest);
    await assert.rejects(release.validate(m), /immutable/);
  }));

test("router pins reject floating images and mismatched registry digests", () => {
  const pin = { version: "0.1.0", sha: base, image: `ghcr.io/mickey-kras/hindsight-memory-router@${digest}`, dockerhub_image: `docker.io/mickeykrasilnikov/hindsight-memory-router@${digest}` };
  release.validateRouter(pin);
  for (const change of [{ image: "ghcr.io/mickey-kras/hindsight-memory-router:latest" }, { sha: "main" }, { dockerhub_image: pin.dockerhub_image.replace("cccc", "dddd") }]) {
    assert.throws(() => release.validateRouter({ ...pin, ...change }));
  }
});

test("integration preparation requires a published immutable router for exactly the same Hindsight", async () => {
  const m = mock();
  const bytes = Buffer.from(`commit=${sha}\nversion=0.1.0\nghcr=ghcr.io/mickey-kras/hindsight-memory-router@${digest}\ndockerhub=docker.io/mickeykrasilnikov/hindsight-memory-router@${digest}\n`);
  const published = { id: 8, tag_name: "v0.1.0", immutable: true, draft: false, prerelease: false };
  m.github.rest.repos.getLatestRelease = () => ({ data: published });
  m.state.refs["tags/v0.1.0"] = { object: { type: "commit", sha } };
  m.state.prepared = { schema: 2, version: "0.1.0", hindsight: pin, packages: [] };
  m.state.assets = [{ id: 9, name: "image-digests.txt", digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}` }];
  m.github.rest.repos.getReleaseAsset = () => ({ data: bytes });
  assert.equal((await release.releasedRouter(m.github, pin)).sha, sha);
  await assert.rejects(release.releasedRouter(m.github, { ...pin, sha }), /current Hindsight/);
  published.immutable = false;
  await assert.rejects(release.releasedRouter(m.github, pin), /immutable router/);
  published.immutable = true;
  m.state.assets[0].digest = digest;
  await assert.rejects(release.releasedRouter(m.github, pin), /checksum/);
});

test("unchanged integration artifacts can be reused but changed bytes need a new package version", async () => {
  const m = mock();
  m.state.releases = [{ id: 1, tag_name: "v0.1.0", draft: false }];
  const pkg = { path: "packages/example-0.12.0.tgz", sha256: "c".repeat(64) };
  m.state.assets = [{ name: "example-0.12.0.tgz", digest }];
  await release.checkPackageReuse(m.github, m.context.repo, [pkg]);
  await assert.rejects(release.checkPackageReuse(m.github, m.context.repo, [{ ...pkg, sha256: "f".repeat(64) }]), /different bytes/);
  await release.checkPackageReuse(m.github, m.context.repo, [{ ...pkg, path: "packages/example-0.12.1.tgz" }]);
});

 test("preparation refuses a main update during upstream resolution before creating the branch", () =>
  fixture(async () => {
    const m = mock();
    m.context.eventName = "workflow_dispatch";
    m.context.ref = "refs/heads/main";
    m.context.sha = base;
    m.inspect = () => {
      m.state.refs["heads/main"].object.sha = sha;
      return digest;
    };
    await assert.rejects(release.prepare(m), /Main advanced while freezing/);
    assert.ok(!m.state.calls.some((call) => call.startsWith("refs/heads/release/")));
  }));

 test("redacted bypass actors require an owner review of the current ruleset revision", () =>
  fixture(async () => {
    const rule = { ...rulesets(123)[0], id: 41, updated_at: "2026-09-11T00:00:00Z" };
    delete rule.bypass_actors;
    const previous = process.env.RELEASE_SETTINGS_REVIEW;
    delete process.env.RELEASE_SETTINGS_REVIEW;
    const check = () => release.checkRule(rule, "branch", "refs/heads/release/*", ["creation"], 123);
    try {
      assert.throws(check, /owner-reviewed/);
      process.env.RELEASE_SETTINGS_REVIEW = JSON.stringify({ app_id: 123, immutable_releases: true, rulesets: { 41: rule.updated_at } });
      check();
      process.env.RELEASE_SETTINGS_REVIEW = JSON.stringify({ app_id: 123, immutable_releases: true, rulesets: { 41: "2026-09-10T17:00:00.000-07:00" } });
      check();
      rule.updated_at = "2026-09-11T00:00:00.001Z";
      assert.throws(check, /owner-reviewed/);
      rule.updated_at = "2026-09-11T00:01:00Z";
      assert.throws(check, /owner-reviewed/);
      process.env.RELEASE_SETTINGS_REVIEW = "invalid";
      assert.throws(check, /Invalid RELEASE_SETTINGS_REVIEW/);
    } finally {
      if (previous === undefined) delete process.env.RELEASE_SETTINGS_REVIEW;
      else process.env.RELEASE_SETTINGS_REVIEW = previous;
    }
  }));

 test("upstream retries transient failures without hiding unavailable or invalid inputs", async () => {
  const waits = [];
  let attempts = 0;
  assert.equal(await release.retry(async () => {
    if (++attempts < 3) throw Object.assign(new Error("unavailable"), { status: 503 });
    return "resolved";
  }, async (ms) => waits.push(ms)), "resolved");
  assert.deepEqual(waits, [1000, 2000]);
  await assert.rejects(release.retry(async () => { throw Object.assign(new Error("missing"), { status: 404 }); }, async () => assert.fail("must not retry missing versions")), /missing/);
 });

test("follow-up versions derive only from the release workflow ref", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    assert.equal(release.publishedVersion(m.context), "0.1.0");
    assert.equal(release.nextPatch("0.1.0"), "0.1.1");
    assert.equal(release.nextPatch("1.9.9"), "1.9.10");
    assert.throws(() => release.nextPatch("0.1"), /Invalid released version/);
    m.context.eventName = "workflow_dispatch";
    assert.throws(() => release.publishedVersion(m.context), /only from main/);
    m.context.eventName = "push";
    m.context.ref = "refs/heads/main";
    assert.throws(() => release.publishedVersion(m.context), /release branch/);
    m.context.ref = "refs/heads/release/0.1";
    assert.throws(() => release.publishedVersion(m.context), /Invalid release candidate/);
  }));

function publishedFixture(m) {
  prepared(m);
  m.state.refs["tags/v0.1.0"] = { object: { type: "commit", sha } };
  const files = {
    "release-version.json": `${JSON.stringify({ version: "0.1.0" }, null, 2)}\n`,
    "pyproject.toml": '[project]\nversion = "0.1.0"\n',
  };
  m.github.rest.repos.getContent = async ({ path }) => ({
    data: { type: "file", encoding: "base64", content: Buffer.from(files[path]).toString("base64") },
  });
  return files;
}

test("follow-up opens a next-patch bump PR on main and never repeats it", () =>
  fixture(async () => {
    const m = mock();
    const files = publishedFixture(m);
    await release.bumpReleasedVersion(m);
    assert.deepEqual(m.state.calls, ["tree", "commit", "refs/heads/ci/bump-release-version-0-1-1", "pr:ci/bump-release-version-0-1-1", "merge:7"]);
    assert.equal(m.state.pull.base.ref, "main");
    assert.deepEqual(m.state.merge, { repository: "example/hindsight-memory-router", number: 7, sha });
    const tree = Object.fromEntries(m.state.tree.map((item) => [item.path, item.content]));
    assert.deepEqual(JSON.parse(tree["release-version.json"]), { version: "0.1.1" });
    assert.equal(tree["pyproject.toml"], '[project]\nversion = "0.1.1"\n');
    m.state.calls.length = 0;
    m.state.pulls = [{ number: 7 }];
    await release.bumpReleasedVersion(m);
    assert.deepEqual(m.state.calls, ["merge:7"], "an open bump PR must be reused and queued");
    m.state.calls.length = 0;
    m.state.pull.auto_merge = { merge_method: "squash" };
    await release.bumpReleasedVersion(m);
    assert.deepEqual(m.state.calls, [], "already queued PRs must not be queued again");
    m.state.pulls = [];
    files["release-version.json"] = `${JSON.stringify({ version: "0.2.0" }, null, 2)}\n`;
    await release.bumpReleasedVersion(m);
    assert.deepEqual(m.state.calls, [], "a main that moved on must not be bumped");
    m.state.refs["heads/ci/bump-release-version-0-1-1"] = { object: { type: "commit", sha: base } };
    files["release-version.json"] = `${JSON.stringify({ version: "0.1.0" }, null, 2)}\n`;
    await release.bumpReleasedVersion(m);
    assert.deepEqual(m.state.calls, ["tree", "commit", "delete:heads/ci/bump-release-version-0-1-1", "refs/heads/ci/bump-release-version-0-1-1", "pr:ci/bump-release-version-0-1-1", "merge:7"], "a stale bump branch must be recreated");
  }));

test("follow-up retries a failed auto-merge without recreating the bump", () =>
  fixture(async () => {
    const m = mock();
    publishedFixture(m);
    m.state.failMerge = true;
    await assert.rejects(release.bumpReleasedVersion(m), /auto-merge unavailable/);
    m.state.calls.length = 0;
    m.state.failMerge = false;
    await release.bumpReleasedVersion(m);
    assert.deepEqual(m.state.calls, ["merge:7"]);
  }));

test("follow-up refuses modified or retargeted bump PRs on retry", () =>
  fixture(async () => {
    const m = mock();
    publishedFixture(m);
    await release.bumpReleasedVersion(m);
    m.state.calls.length = 0;
    m.state.pull.base.ref = "release/0.1.0";
    await assert.rejects(release.bumpReleasedVersion(m), /not the expected bump/);
    m.state.pull.base.ref = "main";
    m.state.pull.draft = true;
    await assert.rejects(release.bumpReleasedVersion(m), /not the expected bump/);
    m.state.pull.draft = false;
    const original = (await m.github.rest.pulls.listFiles()).data;
    for (const files of [
      [...original, { filename: "memory_router/config.py" }],
      [original[0], { ...original[1], patch: original[1].patch.replace('version = "0.1.1"', 'version = "0.2.0"') }],
      [original[0], { ...original[1], patch: undefined }],
      [original[0], original[0]],
    ]) {
      m.state.bumpFiles = files;
      await assert.rejects(release.bumpReleasedVersion(m), /beyond the next patch/);
    }
    assert.deepEqual(m.state.calls, []);
  }));

test("follow-up bump refuses unpublished versions and misaligned main files", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    await assert.rejects(release.bumpReleasedVersion(m), /not published/);
    const files = publishedFixture(m);
    m.state.refs["tags/v0.1.0"].object.sha = base;
    await assert.rejects(release.bumpReleasedVersion(m), /not published/);
    m.state.refs["tags/v0.1.0"].object.sha = sha;
    files["pyproject.toml"] = '[project]\nversion = "0.9.9"\n';
    await assert.rejects(release.bumpReleasedVersion(m), /exactly once/);
    assert.equal(m.state.calls.length, 0);
  }));

test("follow-up deletes the published branch only at its tagged commit", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    await assert.rejects(release.deletePublishedBranch(m), /not published/);
    m.state.refs["tags/v0.1.0"] = { object: { type: "commit", sha: base } };
    await assert.rejects(release.deletePublishedBranch(m), /not published/);
    m.state.refs["tags/v0.1.0"].object.sha = sha;
    m.state.refs["heads/release/0.1.0"].object.sha = base;
    await assert.rejects(release.deletePublishedBranch(m), /advanced past the published commit/);
    m.state.refs["heads/release/0.1.0"].object.sha = sha;
    await release.deletePublishedBranch(m);
    assert.deepEqual(m.state.calls, ["delete:heads/release/0.1.0"]);
    await release.deletePublishedBranch(m);
    assert.deepEqual(m.state.calls, ["delete:heads/release/0.1.0"], "an absent branch must be a no-op");
  }));

test("follow-up prunes stale branches published at their tag and keeps advanced ones", () =>
  fixture(async () => {
    const m = mock();
    publishedFixture(m);
    m.state.releasesByTag = Object.fromEntries(["v0.0.9", "v0.0.8", "v0.0.6"].map((tag) => [tag, { immutable: true, draft: false, prerelease: false }]));
    m.state.branches = [
      { name: "release/0.1.0", commit: { sha } },
      { name: "release/0.0.9", commit: { sha: base } },
      { name: "release/0.0.8", commit: { sha } },
      { name: "release/0.0.7", commit: { sha: base } },
      { name: "release/0.0.6", commit: { sha: base } },
      { name: "release/next", commit: { sha: base } },
      { name: "main", commit: { sha: base } },
    ];
    m.state.refs["heads/release/0.0.9"] = { object: { type: "commit", sha: base } };
    m.state.refs["tags/v0.0.9"] = { object: { type: "commit", sha: base } };
    m.state.refs["tags/v0.0.8"] = { object: { type: "commit", sha: base } };
    m.state.refs["heads/release/0.0.8"] = { object: { type: "commit", sha } };
    m.state.refs["tags/v0.0.6"] = { object: { type: "commit", sha: base } };
    await release.deletePublishedBranch(m);
    assert.deepEqual(m.state.calls, [
      "delete:heads/release/0.1.0",
      "delete:heads/release/0.0.9",
    ]);
    assert.deepEqual(m.state.errors, [], "a branch that vanished mid-run must be tolerated");
    assert.deepEqual(m.state.warnings, ["Kept release/0.0.8: the branch advanced past its published tag"]);
  }));


test("fresh preparation resumes the frozen candidate without resolving newer upstream inputs", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    m.context = { ...m.context, eventName: "workflow_dispatch", workflow: "release", ref: "refs/heads/main", sha: base, runId: 6 };
    m.state.branches = [{ name: "release/0.1.0" }];
    m.inspect = () => assert.fail("recovery must not repin Hindsight");
    await release.prepare(m);
    assert.equal(m.outputs.resume_sha, sha);
    assert.deepEqual(m.state.calls, []);
    m.state.prepared.base = "d".repeat(40);
    await assert.rejects(release.prepare(m), /another main snapshot/);
    assert.deepEqual(m.state.calls, []);
  }));

function recoverable(m, conclusion = "failure") {
  m.state.refs["heads/release/0.1.0"] = { object: { type: "commit", sha } };
  m.state.runs = [{ id: 99, event: "push", head_branch: "release/0.1.0", head_sha: sha,
    path: ".github/workflows/release.yml", status: "completed", conclusion }];
  return { ...m, version: "0.1.0", sha };
}

test("preparation reruns failed jobs and explicitly retries cancelled runs at the frozen SHA", () =>
  fixture(async () => {
    const m = mock();
    await release.resumePreparedRelease(recoverable(m));
    await release.resumePreparedRelease(recoverable(m, "cancelled"));
    assert.deepEqual(m.state.calls, ["rerun-failed:99", "rerun:99"]);
    assert.match(m.state.summary, /Publication is pending/);
  }));

test("repeated preparation leaves active and successful release runs alone", () =>
  fixture(async () => {
    const m = mock();
    const args = recoverable(m);
    m.state.runs[0].status = "in_progress";
    await release.resumePreparedRelease(args);
    assert.match(m.state.summary, /No duplicate release/);
    m.state.runs[0].status = "completed";
    m.state.runs[0].conclusion = "success";
    await release.resumePreparedRelease(args);
    assert.deepEqual(m.state.calls, []);
  }));

test("recovery refuses missing, mismatched, or advanced release candidates", () =>
  fixture(async () => {
    for (const change of [
      (m) => { delete m.state.refs["heads/release/0.1.0"]; },
      (m) => { m.state.refs["heads/release/0.1.0"].object.sha = base; },
      (m) => { m.state.runs[0].head_sha = base; },
      (m) => { m.state.runs[0].event = "pull_request"; },
      (m) => { m.state.runs[0].path = ".github/workflows/publish.yml"; },
      (m) => { m.state.runs = []; },
    ]) {
      const m = mock();
      const args = recoverable(m);
      change(m);
      await assert.rejects(release.resumePreparedRelease(args), release.ReleaseError);
      assert.deepEqual(m.state.calls, []);
    }
    const m = mock();
    const args = recoverable(m);
    m.github.rest.actions.listWorkflowRuns = () => {
      m.state.refs["heads/release/0.1.0"].object.sha = base;
      return { data: m.state.runs };
    };
    await assert.rejects(release.resumePreparedRelease(args), /advanced before retry/);
    assert.deepEqual(m.state.calls, []);
  }));

test("release retries require retained bytes once an immutable tag exists", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    m.state.refs["tags/v0.1.0"] = { object: { type: "commit", sha } };
    m.state.artifacts = [
      { id: 1, name: `image-${sha}`, expired: false },
      { id: 2, name: `image-digests-${sha}-1`, expired: true },
      { id: 3, name: `image-digests-${base}-2`, expired: false },
      { id: 4, name: `image-digests-${sha}-2extra`, expired: false },
    ];
    await assert.rejects(release.retryArtifacts(m), /retained release bytes are missing/);
    m.state.artifacts.push({ id: 5, name: `image-digests-${sha}-2`, expired: false });
    await release.retryArtifacts(m);
    assert.equal(m.outputs.artifact, "1");
    assert.equal(m.outputs.release_assets, "5");
    m.state.artifacts[0].expired = true;
    await assert.rejects(release.retryArtifacts(m), /Saved release image expired/);
  }));

test("partial publication restores its original signature bytes before resuming asset uploads", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    const hash = (path) => `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
    writeFileSync("image-digests.txt", `commit=${sha}\nversion=0.1.0\nsbom=${hash("sbom.cdx.json")}\nui-package=${hash("memory-router-ui-0.2.0.tgz")}\n`);
    mkdirSync("saved");
    for (const path of ["image-digests.txt", "sbom.cdx.json", ...release.uiPackageAssets()]) {
      writeFileSync(join("saved", path), readFileSync(path));
    }
    const upload = m.github.rest.repos.uploadReleaseAsset;
    m.github.rest.repos.uploadReleaseAsset = (args) => {
      const result = upload(args);
      if (args.name.endsWith(".sigstore.json")) throw new Error("upload acknowledgement lost");
      return result;
    };
    await assert.rejects(release.finalize(m), /acknowledgement lost/);
    writeFileSync("memory-router-ui-0.2.0.tgz.sigstore.json", '{"regenerated":"different bytes"}');
    await assert.rejects(release.finalize(m), /Existing release asset differs/);
    release.restoreReleaseAssets({ context: m.context, directory: "saved" });
    await release.finalize(m);
    assert.equal(m.state.release.draft, false);
    assert.equal(m.state.calls.filter((call) => call === "refs/tags/v0.1.0").length, 1);
  }));

test("restoring release assets rejects incomplete inventory, corrupt bytes, and another commit", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    mkdirSync("saved");
    await assert.rejects(async () => release.restoreReleaseAssets({ context: m.context, directory: "saved" }), /ENOENT/);
    for (const path of ["image-digests.txt", "sbom.cdx.json", ...release.uiPackageAssets()]) {
      writeFileSync(join("saved", path), readFileSync(path));
    }
    assert.throws(() => release.restoreReleaseAssets({ context: m.context, directory: "saved" }), /another commit/);
    writeFileSync("saved/image-digests.txt", `commit=${sha}\nversion=0.1.0\nsbom=wrong\n`);
    assert.throws(() => release.restoreReleaseAssets({ context: m.context, directory: "saved" }), /checksum differs/);
  }));

test("full rerun accepts a deleted branch only for its immutable published commit", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    delete m.state.refs["heads/release/0.1.0"];
    await assert.rejects(release.validate(m), /branch is missing/);
    m.state.release = { immutable: false, draft: true, prerelease: false };
    m.state.refs["tags/v0.1.0"] = { object: { type: "commit", sha } };
    await assert.rejects(release.validate(m), /branch is missing/);
    m.state.release = { immutable: true, draft: false, prerelease: false };
    await release.validate(m);
    m.state.refs["tags/v0.1.0"].object.sha = base;
    await assert.rejects(release.validate(m), /not published at this commit/);
  }));


test("preparation does not repeat an immutable publication after branch cleanup", () =>
  fixture(async () => {
    const m = mock();
    prepared(m);
    delete m.state.refs["heads/release/0.1.0"];
    m.context = { ...m.context, eventName: "workflow_dispatch", workflow: "release", ref: "refs/heads/main", sha: base, runId: 6 };
    m.state.tags = [{ name: "v0.1.0" }];
    m.state.refs["tags/v0.1.0"] = { object: { type: "commit", sha } };
    m.state.release = { immutable: true, draft: false, prerelease: false };
    m.inspect = () => assert.fail("completed release must not repin Hindsight");
    await release.prepare(m);
    assert.deepEqual(m.state.calls, []);
    assert.match(m.state.summary, /already published/);
    m.state.release.immutable = false;
    await assert.rejects(release.prepare(m), /incomplete release/);
  }));

test("startup failure recovery retries the caller instead of nonexistent failed jobs", () =>
  fixture(async () => {
    const m = mock();
    await release.resumePreparedRelease(recoverable(m, "startup_failure"));
    assert.deepEqual(m.state.calls, ["rerun:99"]);
  }));


test("published branch pruning retains newer releases awaiting their own follow-up", () =>
  fixture(async () => {
    const m = mock();
    publishedFixture(m);
    m.state.branches = [{ name: "release/0.2.0", commit: { sha } }];
    m.state.refs["heads/release/0.2.0"] = { object: { type: "commit", sha } };
    m.state.refs["tags/v0.2.0"] = { object: { type: "commit", sha } };
    await release.deletePublishedBranch(m);
    assert.deepEqual(m.state.calls, ["delete:heads/release/0.1.0"]);
    assert.equal(m.state.refs["heads/release/0.2.0"].object.sha, sha);
  }));


test("published branch pruning retains tag-only and draft releases", () =>
  fixture(async () => {
    for (const published of [undefined, { immutable: false, draft: true }, { immutable: false, draft: false }]) {
      const m = mock();
      publishedFixture(m);
      m.state.branches = [{ name: "release/0.0.9", commit: { sha: base } }];
      m.state.refs["heads/release/0.0.9"] = { object: { type: "commit", sha: base } };
      m.state.refs["tags/v0.0.9"] = { object: { type: "commit", sha: base } };
      m.state.releasesByTag = { "v0.0.9": published };
      await release.deletePublishedBranch(m);
      assert.deepEqual(m.state.calls, ["delete:heads/release/0.1.0"]);
      assert.equal(m.state.refs["heads/release/0.0.9"].object.sha, base);
    }
  }));

function unified(m) {
  const manifest = prepared(m);
  manifest.publication_run = 5;
  m.state.prepared = structuredClone(manifest);
  put("release.json", manifest);
  m.target = { ref: m.context.ref, sha };
  m.context = { ...m.context, eventName: "workflow_dispatch", ref: "refs/heads/main", sha: base };
  return manifest;
}

test("unified preparation publishes its candidate as outputs without launching another run", () =>
  fixture(async () => {
    const m = mock();
    m.context.workflow = "release";
    await release.prepare(m);
    assert.equal(m.outputs.sha, sha);
    assert.equal(m.outputs.ref, "refs/heads/release/0.1.0");
    const manifest = JSON.parse(m.state.tree.find(file => file.path === "release.json").content);
    assert.equal(manifest.publication_run, m.context.runId);
    assert.equal(manifest.base, base);
    assert.equal(m.outputs.resume_sha, undefined);
  }));

test("a native full rerun reuses acknowledged or unacknowledged preparation after main advances", () =>
  fixture(async () => {
    const m = mock();
    unified(m);
    m.state.branches = [{ name: "release/0.1.0" }];
    m.state.refs["heads/main"].object.sha = "d".repeat(40);
    m.inspect = () => assert.fail("native retry must not resolve new upstream inputs");
    await release.prepare(m);
    assert.equal(m.outputs.sha, sha);
    assert.equal(m.outputs.resume_sha, undefined);
    assert.deepEqual(m.state.calls, []);
    m.state.comparison.total_commits = 2;
    m.state.comparison.commits.push({ sha: "d".repeat(40) });
    await assert.rejects(release.prepare(m), /Candidate changed after preparation/);
  }));

test("a native full rerun survives published branch cleanup and the later version bump", () =>
  fixture(async () => {
    const m = mock();
    unified(m);
    delete m.state.refs["heads/release/0.1.0"];
    m.state.refs["heads/main"].object.sha = "d".repeat(40);
    m.state.refs["tags/v0.1.0"] = { object: { type: "commit", sha } };
    m.state.tags = [{ name: "v0.1.0" }];
    m.state.release = { immutable: true, draft: false, prerelease: false };
    m.inspect = () => assert.fail("completed release must retain its original inputs");
    await release.prepare(m);
    assert.equal(m.outputs.sha, sha);
    await release.validate(m);
    await assert.rejects(release.retryArtifacts(m), /retained release bytes are missing/);
    m.state.artifacts = [{ id: 1, name: `image-${sha}` }, { id: 2, name: `image-digests-${sha}-1` }];
    await release.retryArtifacts(m);
    assert.equal(m.outputs.artifact, "1");
    assert.equal(m.context.sha, base);
    assert.deepEqual(m.state.calls, []);
  }));

test("another release dispatch redirects to the originating main run and preserves its artifacts", () =>
  fixture(async () => {
    const m = mock();
    unified(m);
    m.context.runId = 6;
    m.state.branches = [{ name: "release/0.1.0" }];
    m.state.runs = [{ id: 5, path: ".github/workflows/release.yml", event: "workflow_dispatch",
      head_branch: "main", head_sha: base, status: "completed", conclusion: "failure" }];
    await release.prepare(m);
    assert.equal(m.outputs.sha, undefined);
    assert.equal(m.outputs.resume_run, 5);
    await release.resumePreparedRelease({ ...m, version: "0.1.0", sha, runId: 5 });
    assert.deepEqual(m.state.calls, ["rerun-failed:5"]);
    m.state.runs[0].conclusion = "cancelled";
    await release.resumePreparedRelease({ ...m, version: "0.1.0", sha, runId: 5 });
    assert.equal(m.state.calls.at(-1), "rerun:5");
    m.state.runs[0].head_sha = sha;
    await assert.rejects(release.resumePreparedRelease({ ...m, version: "0.1.0", sha, runId: 5 }), /source snapshot/);
  }));

test("the dispatch candidate keeps frozen compatibility and publishes its own commit", () =>
  fixture(async () => {
    const m = mock();
    unified(m);
    m.inspect = () => assert.fail("candidate validation must not query floating Hindsight");
    assert.deepEqual(await release.resolve(m), { channel: "release", ...pin });
    await release.finalize(m);
    assert.equal(m.state.refs["tags/v0.1.0"].object.sha, sha);
    assert.equal(m.state.release.target_commitish, sha);
    assert.equal(m.context.sha, base);
    assert.equal(m.context.ref, "refs/heads/main");
  }));

test("candidate targets reject unrelated workflows, source snapshots and branch dispatch substitutions", () =>
  fixture(async () => {
    for (const change of [
      m => { m.context.workflow = "main"; },
      m => { m.context.eventName = "pull_request"; },
      m => { m.context.ref = "refs/heads/feature/test"; },
      m => { m.target.sha = "main"; },
      m => { m.target.ref = "refs/heads/release/01.0.0"; },
      m => { m.context.sha = "d".repeat(40); },
      m => { m.context.ref = m.target.ref; },
    ]) {
      const m = mock();
      unified(m);
      change(m);
      await assert.rejects(release.finalize(m), release.ReleaseError);
      assert.deepEqual(m.state.calls, []);
    }
  }));

test("provenance preserves actual workflow claims and binds the separately validated candidate", () =>
  fixture(async () => {
    const m = mock();
    unified(m);
    const previous = process.env.RUNNER_TEMP;
    process.env.RUNNER_TEMP = process.cwd();
    const workflow = { uri: `git+https://github.com/example/hindsight-memory-router@${m.context.ref}`,
      digest: { gitCommit: base } };
    const build = async () => ({ type: "https://slsa.dev/provenance/v1", params: {
      buildDefinition: { resolvedDependencies: [structuredClone(workflow)] },
      runDetails: { builder: { id: "real-oidc-workflow" } },
    } });
    try {
      const result = await release.candidateProvenance({ ...m, build });
      assert.deepEqual(result.params.buildDefinition.resolvedDependencies, [workflow, {
        name: "release-candidate", uri: `git+https://github.com/example/hindsight-memory-router@${m.target.ref}`,
        digest: { gitCommit: sha },
      }]);
      assert.equal(result.params.runDetails.builder.id, "real-oidc-workflow");
      assert.deepEqual(JSON.parse(readFileSync(m.outputs.path, "utf8")), result.params);
      workflow.digest.gitCommit = sha;
      await assert.rejects(release.candidateProvenance({ ...m, build }), /workflow claims differ/);
    } finally {
      if (previous === undefined) delete process.env.RUNNER_TEMP;
      else process.env.RUNNER_TEMP = previous;
    }
  }));

test("non-main dispatches fail before preparation can inspect or mutate the repository", async () => {
  const github = new Proxy({}, { get() { assert.fail("entry rejection must precede GitHub access"); } });
  for (const ref of ["refs/heads/release/0.1.0", "refs/heads/fix/release", "refs/tags/v0.1.0"]) {
    const context = { workflow: "release", eventName: "workflow_dispatch", ref, sha: base };
    await assert.rejects(release.prepare({ github, context }), /Release dispatch is allowed only from main/);
  }
});
