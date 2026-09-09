const { test } = require('node:test');
const assert = require('node:assert/strict');
const { run } = require('./pr-branch-updater.cjs');

function fixture({ mergeable = true, ahead = 1, fail = false, fork = false, user } = {}) {
  const calls = { updates: [], sleeps: [], failures: [], comparisons: [] };
  let reads = 0;
  const pull = { number: 1, user, state: 'open', base: { ref: 'main', sha: 'base' },
    head: { sha: 'head', repo: { full_name: fork ? 'other/repo' : 'owner/repo' } } };
  const github = {
    paginate: async () => [pull],
    rest: {
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

test('leaves stale Dependabot branches to scheduled native rebasing', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 49699333 } });
  await run(args);
  assert.deepEqual(calls.updates, []);
  assert.deepEqual(calls.failures, []);
});
test('does not involve Dependabot when its branch is current', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 49699333 }, ahead: 0 });
  await run(args);
  assert.deepEqual(calls.updates, []);
});
test('a bot-like name alone does not bypass branch updates', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 1 } });
  await run(args);
  assert.equal(calls.updates.length, 1);
});
