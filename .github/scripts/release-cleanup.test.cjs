const test = require("node:test");
const assert = require("node:assert/strict");
const cleanup = require("./release-cleanup.cjs");

const sha = "b".repeat(40);
const digest = `sha256:${"c".repeat(64)}`;
const otherDigest = `sha256:${"d".repeat(64)}`;
const referrerDigest = `sha256:${"e".repeat(64)}`;

function fakeContext(overrides = {}) {
  return {
    eventName: "push",
    workflow: "release",
    ref: "refs/heads/release/0.1.0",
    sha,
    actor: "mickey-kras",
    repo: { owner: "mickey-kras", repo: "hindsight-memory-router" },
    payload: { repository: { owner: { type: "User" } } },
    ...overrides,
  };
}

function fakeCore() {
  const state = { errors: [], warnings: [], summary: "" };
  const summary = {
    addHeading(text) {
      state.summary += `${text}\n`;
      return summary;
    },
    addRaw(text) {
      state.summary += text;
      return summary;
    },
    async write() {},
  };
  return {
    state,
    core: {
      summary: summary,
      error: (message) => state.errors.push(message),
      warning: (message) => state.warnings.push(message),
    },
  };
}

const ENV = ["IMAGE_GHCR", "IMAGE_DOCKERHUB", "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "CLEANUP_DIGEST", "GITHUB_TOKEN"];

async function withEnv(values, fn) {
  const before = Object.fromEntries(ENV.map((key) => [key, process.env[key]]));
  for (const key of ENV) {
    if (values[key] === undefined) delete process.env[key];
    else process.env[key] = values[key];
  }
  try {
    await fn();
  } finally {
    for (const key of ENV) {
      if (before[key] === undefined) delete process.env[key];
      else process.env[key] = before[key];
    }
  }
}

const registryEnv = {
  IMAGE_GHCR: "ghcr.io/mickey-kras/hindsight-memory-router",
  IMAGE_DOCKERHUB: "docker.io/mickeykrasilnikov/hindsight-memory-router",
  DOCKERHUB_USERNAME: "hub-user",
  DOCKERHUB_TOKEN: "hub-token",
  GITHUB_TOKEN: "github-token",
};

function ghcrGithub(versions, deleted) {
  return {
    paginate: async () => versions,
    rest: {
      packages: {
        deletePackageVersionForAuthenticatedUser: async ({ package_version_id }) => {
          if (package_version_id === 404) throw Object.assign(new Error("gone"), { status: 404 });
          deleted.push(package_version_id);
        },
      },
    },
  };
}

function response(status, body = {}) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

test("targets accepts only release workflow refs", () => {
  assert.deepEqual(cleanup.targets(fakeContext()), { version: "0.1.0", sha });
  for (const ref of ["refs/heads/main", "refs/heads/release/0.1", "refs/heads/release/1.0.0-latest"]) {
    assert.throws(() => cleanup.targets(fakeContext({ ref })), cleanup.CleanupError);
  }
  assert.throws(() => cleanup.targets(fakeContext({ workflow: "main" })), cleanup.CleanupError);
  assert.throws(() => cleanup.targets(fakeContext({ eventName: "workflow_dispatch" })), cleanup.CleanupError);
});

test("registries keeps every tag once a git tag or release exists", async () => {
  const { core, state } = fakeCore();
  const github = {
    rest: {
      git: { getRef: async () => ({ data: {} }) },
      repos: { getReleaseByTag: async () => ({ data: {} }) },
      packages: {},
    },
  };
  await cleanup.registries({ github, context: fakeContext(), core });
  assert.match(state.summary, /keeping every registry tag/);
  assert.equal(state.errors.length, 0);
});

test("cleanupGhcr deletes only this run's tags, artifacts, and referrers", async () => {
  const versions = [
    { id: 1, name: digest, metadata: { container: { tags: ["0.1.0", sha] } } },
    { id: 2, name: referrerDigest, metadata: { container: { tags: [`${digest.replace(":", "-")}.sig`] } } },
    { id: 3, name: referrerDigest, metadata: { container: { tags: [] } } },
    { id: 4, name: otherDigest, metadata: { container: { tags: ["latest"] } } },
    { id: 5, name: otherDigest, metadata: { container: { tags: ["0.2.0"] } } },
    { id: 404, name: digest, metadata: { container: { tags: [`${digest.replace(":", "-")}.att`] } } },
  ];
  const deleted = [];
  const fetchImpl = async (url) => {
    if (url.startsWith("https://ghcr.io/token")) return response(200, { token: "registry-token" });
    if (url.includes(`/referrers/${digest}`)) return response(200, { manifests: [{ digest: referrerDigest }] });
    return response(404);
  };
  await withEnv(registryEnv, async () => {
    const { core } = fakeCore();
    const removed = await cleanup.cleanupGhcr(ghcrGithub(versions, deleted), fakeContext(), core, "0.1.0", sha, fetchImpl);
    assert.deepEqual(deleted.sort(), [1, 2, 3]);
    assert.equal(removed.length, 3);
  });
});

test("cleanupGhcr refuses tags that moved to another digest", async () => {
  const versions = [{ id: 1, name: otherDigest, metadata: { container: { tags: ["0.1.0", sha] } } }];
  const deleted = [];
  await withEnv({ ...registryEnv, CLEANUP_DIGEST: digest }, async () => {
    const { core, state } = fakeCore();
    const removed = await cleanup.cleanupGhcr(ghcrGithub(versions, deleted), fakeContext(), core, "0.1.0", sha, async () => {
      throw new Error("referrers must not be queried without owned subjects");
    });
    assert.deepEqual(deleted, []);
    assert.deepEqual(removed, []);
    assert.equal(state.warnings.length, 1);
  });
});

test("cleanupDockerHub refuses tags that moved to another digest", async () => {
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push(`${options.method ?? "GET"} ${url}`);
    if (url === "https://hub.docker.com/v2/users/login") return response(200, { token: "jwt" });
    if (url.endsWith("/tags/0.1.0")) return response(200, { digest: otherDigest });
    if (url.endsWith(`/tags/${sha}`)) return response(404);
    if (url.includes("auth.docker.io/token")) return response(200, { token: "registry-token" });
    if (options.method === "DELETE") throw new Error("moved tags must never be deleted");
    return response(404);
  };
  await withEnv({ ...registryEnv, CLEANUP_DIGEST: digest }, async () => {
    const { core, state } = fakeCore();
    const removed = await cleanup.cleanupDockerHub(core, "0.1.0", sha, fetchImpl);
    assert.deepEqual(removed, []);
    assert.equal(state.warnings.length, 1);
    assert.match(state.warnings[0], /0\.1\.0 now resolves to another digest/);
    assert.equal(calls.filter((call) => call.startsWith("DELETE")).length, 0);
  });
});

test("attempt records failures in the summary instead of throwing", async () => {
  const { core, state } = fakeCore();
  await cleanup.attempt(core, core.summary, "Broken", async () => {
    throw new Error("boom");
  });
  await cleanup.attempt(core, core.summary, "Empty", async () => []);
  await cleanup.attempt(core, core.summary, "Removed", async () => ["0.1.0"]);
  assert.deepEqual(state.errors, ["Broken cleanup failed: boom"]);
  assert.match(state.summary, /Broken: \*\*failed\*\* \(boom\); remove the orphaned tags manually/);
  assert.match(state.summary, /Empty: nothing left to delete/);
  assert.match(state.summary, /Removed: deleted `0\.1\.0`/);
});

test("registries aborts without deleting when the published probe errors", async () => {
  const { core, state } = fakeCore();
  const github = {
    paginate: async () => {
      throw new Error("package versions must not be listed after a failed probe");
    },
    rest: {
      git: {
        getRef: async () => {
          throw Object.assign(new Error("API outage"), { status: 500 });
        },
      },
      repos: { getReleaseByTag: async () => ({ data: {} }) },
      packages: {},
    },
  };
  const fetchImpl = async () => {
    throw new Error("registries must not be queried after a failed probe");
  };
  await assert.rejects(cleanup.registries({ github, context: fakeContext(), core, fetchImpl }), /API outage/);
  assert.match(state.summary, /Aborted before any deletion: API outage/);
});

test("cleanupDockerHub deletes scoped tags and tolerates missing ones", async () => {
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push(`${options.method ?? "GET"} ${url}`);
    if (url === "https://hub.docker.com/v2/users/login") return response(200, { token: "jwt" });
    if (url === "https://hub.docker.com/v2/repositories/mickeykrasilnikov/hindsight-memory-router/tags/0.1.0") {
      return options.method === "DELETE" ? response(204) : response(200, { digest });
    }
    if (url.includes("auth.docker.io/token")) return response(200, { token: "registry-token" });
    if (url.includes(`/referrers/${digest}`)) return response(200, { manifests: [{ digest: referrerDigest }] });
    if (url.includes(`/manifests/${referrerDigest}`)) return response(202);
    if (url.endsWith(`.sig`) || url.endsWith(`.att`)) return response(404);
    return response(404);
  };
  await withEnv({ ...registryEnv, CLEANUP_DIGEST: digest }, async () => {
    const { core } = fakeCore();
    const removed = await cleanup.cleanupDockerHub(core, "0.1.0", sha, fetchImpl);
    assert.deepEqual(removed, [`${referrerDigest} (referrer)`, "0.1.0"]);
    const deletions = calls.filter((call) => call.startsWith("DELETE"));
    assert.equal(deletions.filter((call) => call.includes("latest")).length, 0);
    assert.equal(deletions.length, 4);
  });
});

test("branch deletion skips published, advanced, and absent branches", async () => {
  const { core, state } = fakeCore();
  const notFound = () => Promise.reject(Object.assign(new Error("Not Found"), { status: 404 }));
  const github = (head) => {
    const api = {
      deleted: false,
      rest: {
        git: {
          getRef: async ({ ref }) => {
            if (ref.startsWith("tags/")) return notFound();
            if (head === null) return notFound();
            return { data: { object: { sha: head } } };
          },
          deleteRef: async () => {
            api.deleted = true;
          },
        },
        repos: { getReleaseByTag: notFound },
      },
    };
    return api;
  };
  const stale = github("f".repeat(40));
  await cleanup.branch({ github: stale, context: fakeContext(), core });
  assert.equal(stale.deleted, false);
  assert.match(state.summary, /branch advanced/);

  const absent = github(null);
  await cleanup.branch({ github: absent, context: fakeContext(), core });
  assert.equal(absent.deleted, false);

  const current = github(sha);
  await cleanup.branch({ github: current, context: fakeContext(), core });
  assert.equal(current.deleted, true);
});

function dispatchContext(runId = 99) {
  return fakeContext({
    eventName: "workflow_dispatch",
    workflow: "main",
    ref: "refs/heads/main",
    runId,
  });
}

function preparationGithub(branches, deleted) {
  const encode = (value) => ({
    data: { type: "file", encoding: "base64", content: Buffer.from(`${JSON.stringify(value)}\n`).toString("base64") },
  });
  return {
    paginate: async () => branches.map((branch) => ({ name: branch.name })),
    rest: {
      repos: {
        getContent: async ({ ref }) => {
          const branch = branches.find((item) => item.name === ref);
          if (!branch || !branch.manifest) throw Object.assign(new Error("Not Found"), { status: 404 });
          return encode(branch.manifest);
        },
        getReleaseByTag: async ({ tag }) => {
          const branch = branches.find((item) => `v${item.manifest?.version}` === tag && item.published);
          if (!branch) throw Object.assign(new Error("Not Found"), { status: 404 });
          return { data: {} };
        },
      },
      git: {
        getRef: async ({ ref }) => {
          const branch = branches.find((item) => `v${item.manifest?.version}` === ref.slice("tags/".length) && item.published);
          if (!branch) throw Object.assign(new Error("Not Found"), { status: 404 });
          return { data: {} };
        },
        deleteRef: async ({ ref }) => {
          if (ref === "heads/release/0.4.0") throw new Error("forbidden");
          deleted.push(ref);
        },
      },
    },
  };
}

test("preparation cleanup accepts only the main dispatch context", async () => {
  const { core } = fakeCore();
  const github = preparationGithub([], []);
  await assert.rejects(cleanup.preparation({ github, context: fakeContext(), core }), /main workflow button/);
  const wrongRef = { ...dispatchContext(), ref: "refs/heads/release/0.2.0" };
  await assert.rejects(cleanup.preparation({ github, context: wrongRef, core }), /main workflow button/);
});

test("preparation cleanup deletes only this run's unpublished release branches", async () => {
  const { core, state } = fakeCore();
  const branches = [
    { name: "release/0.2.0", manifest: { version: "0.2.0", preparation_run: 99 } },
    { name: "release/0.3.0", manifest: { version: "0.3.0", preparation_run: 42 } },
    { name: "release/0.3.1", manifest: { version: "0.3.1", preparation_run: 99 }, published: true },
    { name: "release/0.4.0", manifest: { version: "0.4.0", preparation_run: 99 } },
    { name: "release/not-a-version", manifest: { version: "x", preparation_run: 99 } },
    { name: "release/0.5.0", manifest: null },
    { name: "main" },
  ];
  const deleted = [];
  await cleanup.preparation({ github: preparationGithub(branches, deleted), context: dispatchContext(), core });
  assert.deepEqual(deleted, ["heads/release/0.2.0"]);
  assert.deepEqual(state.errors, ["Branch `release/0.4.0` cleanup failed: forbidden"]);
  assert.match(state.summary, /Kept `release\/0\.3\.1`/);
  assert.doesNotMatch(state.summary, /release\/0\.3\.0`: deleted/);
});

test("preparation cleanup is a no-op without matching branches", async () => {
  const { core, state } = fakeCore();
  const deleted = [];
  await cleanup.preparation({ github: preparationGithub([{ name: "main" }], deleted), context: dispatchContext(), core });
  assert.deepEqual(deleted, []);
  assert.equal(state.errors.length, 0);
});
