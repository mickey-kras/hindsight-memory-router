const { test } = require('node:test');
const assert = require('node:assert/strict');
const { run } = require('./pr-branch-updater.cjs');

function fixture({ mergeable = true, ahead = 1, fail = false, fork = false, user, comments = [] } = {}) {
  const calls = { updates: [], sleeps: [], failures: [], comparisons: [], comments: [] };
  let reads = 0;
  const pull = { number: 1, user, state: 'open', base: { ref: 'main', sha: 'base' },
    head: { sha: 'head', repo: { full_name: fork ? 'other/repo' : 'owner/repo' } } };
  const github = {
    paginate: async (method) => method === github.rest.issues.listComments ? comments : [pull],
    rest: {
      issues: { listComments: () => {}, createComment: async (args) => {
        if (fail) throw new Error('API unavailable');
        calls.comments.push(args);
      } },
      git: { getRef: async (args) => {
        assert.equal(args.ref, 'heads/main');
        return { data: { object: { sha: 'current-main' } } };
      } },
      pulls: { list: () => {}, get: async () => ({ data: { ...pull,
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

test('requests native Dependabot rebasing without updating workflow files itself', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 49699333 } });
  await run(args);
  assert.deepEqual(calls.updates, []);
  assert.match(calls.comments[0].body, /^@dependabot rebase/);
  assert.deepEqual(calls.failures, []);
});
test('does not repeat a request for the same head and main commits', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 49699333 },
    comments: [{ user: { id: 41898282 }, body: '<!-- dependabot-rebase:head:current-main -->' }] });
  await run(args);
  assert.deepEqual(calls.comments, []);
});
test('does not request a rebase when Dependabot is current', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 49699333 }, ahead: 0 });
  await run(args);
  assert.deepEqual(calls.comments, []);
});
test('failed rebase request fails the updater', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 49699333 }, fail: true });
  await run(args);
  assert.equal(calls.failures.length, 1);
});
test('a bot-like name alone does not bypass branch updates', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 1 } });
  await run(args);
  assert.equal(calls.updates.length, 1);
});
