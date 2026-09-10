const { test } = require('node:test');
const assert = require('node:assert/strict');
const { run } = require('./pr-branch-updater.cjs');

const bot = { login: 'dependabot[bot]', id: 49699333 };

function fixture({ mergeable = true, ahead = 1, fail = false, fork = false, user,
  commits = [{ author: bot, commit: { verification: { verified: true } } }],
  comments = [], changed = false } = {}) {
  const calls = { updates: [], sleeps: [], failures: [], comparisons: [], comments: [] };
  let reads = 0;
  const pull = { number: 1, user, state: 'open', base: { ref: 'main', sha: 'base' },
    head: { sha: 'head', ref: 'dependabot/npm/test', repo: { full_name: fork ? 'other/repo' : 'owner/repo' } } };
  let pullReads = 0;
  const github = {
    paginate: async route => route === github.rest.pulls.listCommits ? commits :
      route === github.rest.issues.listComments ? comments : [pull],
    rest: {
      issues: {
        listComments: () => {},
        createComment: async args => {
          if (fail) throw new Error('API unavailable');
          calls.comments.push(args);
        },
      },
      git: { getRef: async (args) => {
        assert.equal(args.ref, 'heads/main');
        return { data: { object: { sha: 'current-main' } } };
      } },
      pulls: { list: () => {}, listCommits: () => {}, get: async () => ({ data: { ...pull,
        head: changed && pullReads++ > 0 ? { ...pull.head, sha: 'new-head' } : pull.head,
        mergeable: Array.isArray(mergeable) ? mergeable[Math.min(reads++, mergeable.length - 1)] : mergeable,
        mergeable_state: 'blocked',
      } }) },
      repos: { compareCommitsWithBasehead: async (args) => {
        calls.comparisons.push(args.basehead);
        return { data: { ahead_by: args.basehead.endsWith('...base') ? 0 : ahead } };
      } },
    },
    request: async (_route, args) => {
      if (fail) throw new Error('API unavailable');
      calls.updates.push(args);
    },
  };
  const summary = { addHeading: () => summary, addTable: () => summary, write: async () => {} };
  return { calls, args: { github, context: { repo: { owner: 'owner', repo: 'repo' } },
    core: { info: () => {}, summary, setFailed: (s) => calls.failures.push(s) },
    sleep: async (ms) => calls.sleeps.push(ms) } };
}

test('updates against current main despite stale PR base metadata and blocked checks', async () => {
  const { args, calls } = fixture(); await run(args);
  assert.deepEqual(calls.comparisons, ['head...current-main']);
  assert.equal(calls.updates[0].expected_head_sha, 'head');
});
test('retries unknown mergeability and then updates', async () => {
  const { args, calls } = fixture({ mergeable: [null, true] }); await run(args);
  assert.equal(calls.sleeps.length, 1); assert.equal(calls.updates.length, 1);
});
test('persistent unknown fails after bounded retries', async () => {
  const { args, calls } = fixture({ mergeable: null }); await run(args);
  assert.equal(calls.sleeps.length, 3); assert.equal(calls.failures.length, 1);
});
for (const [name, options] of Object.entries({ current: { ahead: 0 }, conflict: { mergeable: false }, fork: { fork: true } })) {
  test(`does not update ${name}`, async () => {
    const { args, calls } = fixture(options); await run(args);
    assert.equal(calls.updates.length, 0); assert.equal(calls.failures.length, 0);
  });
}
test('API failure is not reported as success', async () => {
  const { args, calls } = fixture({ fail: true }); await run(args);
  assert.equal(calls.failures.length, 1);
});

test('requests immediate recreation of a verified stale Dependabot branch', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 49699333 } });
  await run(args);
  assert.deepEqual(calls.updates, []);
  assert.deepEqual(calls.failures, []);
  assert.equal(calls.comments[0].body, '@dependabot recreate\n\n<!-- dependency-refresh:head -->');
});
test('does not involve Dependabot when its branch is current', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 49699333 }, ahead: 0 });
  await run(args);
  assert.deepEqual(calls.updates, []);
  assert.deepEqual(calls.comments, []);
});
test('a bot-like name alone does not bypass branch updates', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 1 } });
  await run(args);
  assert.equal(calls.updates.length, 1);
});

test('does not repeat a recreation request for the same head', async () => {
  const { args, calls } = fixture({ user: bot, comments: [{
    body: '@dependabot recreate\n\n<!-- dependency-refresh:head -->', user: { id: 41898282 },
  }] });
  await run(args);
  assert.deepEqual(calls.comments, []);
});

test('does not let an unrelated comment suppress recreation', async () => {
  const { args, calls } = fixture({ user: bot, comments: [{
    body: '@dependabot recreate\n\n<!-- dependency-refresh:head -->', user: { id: 1 },
  }] });
  await run(args);
  assert.equal(calls.comments.length, 1);
});

for (const commits of [[], [{ author: bot, commit: { verification: { verified: false } } }],
  [{ author: { login: 'owner', id: 1 }, commit: { verification: { verified: true } } }]]) {
  test('refuses recreation of unverified commits', async () => {
    const { args, calls } = fixture({ user: bot, commits });
    await run(args);
    assert.deepEqual(calls.comments, []);
    assert.equal(calls.failures.length, 1);
  });
}

test('uses the caller verifier for prepared dependency commits', async () => {
  const commits = [{ sha: 'generated' }];
  const { args, calls } = fixture({ user: bot, commits });
  let verified = false;
  args.verifyCommits = async (_github, repo, pull, actual) => {
    assert.deepEqual(repo, { owner: 'owner', repo: 'repo' });
    assert.equal(pull.head.sha, 'head');
    assert.equal(actual, commits);
    verified = true;
  };
  await run(args);
  assert.equal(verified, true);
  assert.equal(calls.comments.length, 1);
});

test('does not recreate when the caller verifier rejects generated commits', async () => {
  const { args, calls } = fixture({ user: bot });
  args.verifyCommits = async () => { throw new Error('Unexpected source edit'); };
  await run(args);
  assert.deepEqual(calls.comments, []);
  assert.equal(calls.failures.length, 1);
});

test('does not recreate a head changed during verification', async () => {
  const { args, calls } = fixture({ user: bot, changed: true });
  await run(args);
  assert.deepEqual(calls.comments, []);
});

test('recreates verified Dependabot branches even with merge conflicts', async () => {
  const { args, calls } = fixture({ user: bot, mergeable: false });
  await run(args);
  assert.equal(calls.comments.length, 1);
  assert.deepEqual(calls.updates, []);
});

test('reports failed recreation requests', async () => {
  const { args, calls } = fixture({ user: bot, fail: true });
  await run(args);
  assert.equal(calls.failures.length, 1);
});
