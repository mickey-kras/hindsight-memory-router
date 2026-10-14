const { test } = require('node:test');
const assert = require('node:assert/strict');
const { run } = require('./pr-branch-updater.cjs');

function fixture({ mergeable = true, ahead = 1, fail = false, fork = false, user,
  autoMerge = { merge_method: 'squash' } } = {}) {
  const calls = { updates: [], sleeps: [], failures: [], comparisons: [], logs: [], lists: [], reads: [] };
  let reads = 0;
  const pull = { number: 1, user, auto_merge: autoMerge, state: 'open', base: { ref: 'main', sha: 'base' },
    head: { sha: 'head', repo: { full_name: fork ? 'other/repo' : 'owner/repo' } } };
  const github = {
    paginate: async (_method, options) => { calls.lists.push(options); return [pull]; },
    rest: {
      git: { getRef: async (args) => {
        assert.equal(args.ref, 'heads/main');
        return { data: { object: { sha: 'current-main' } } };
      } },
      pulls: { list: () => {}, get: async (options) => {
        calls.reads.push(options.pull_number);
        return { data: { ...pull,
          mergeable: Array.isArray(mergeable) ? mergeable[Math.min(reads++, mergeable.length - 1)] : mergeable,
          mergeable_state: 'blocked',
        } };
      } },
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
  return { calls, args: { github, mode: 'automatic', context: {
    repo: { owner: 'owner', repo: 'repo' }, eventName: 'push', ref: 'refs/heads/main',
  },
    core: { info: (s) => calls.logs.push(s), summary, setFailed: (s) => calls.failures.push(s) },
    sleep: async (ms) => calls.sleeps.push(ms) } };
}

test('updates against current main despite stale PR base metadata and blocked checks', async () => {
  const { args, calls } = fixture(); await run(args);
  assert.deepEqual(calls.comparisons, ['head...current-main']);
  assert.equal(calls.updates[0].expected_head_sha, 'head');
});
test('a direct manual dispatch refreshes exactly its selected PR without auto-merge', async () => {
  const { args, calls } = fixture({ autoMerge: null });
  args.context.eventName = 'workflow_dispatch';
  args.mode = 'manual';
  args.pullNumber = '17';
  await run(args);
  assert.deepEqual(calls.lists, []);
  assert.deepEqual(calls.reads, [17]);
  assert.equal(calls.updates[0].pull_number, 17);
  assert.equal(calls.updates[0].expected_head_sha, 'head');
});
for (const pullNumber of [undefined, '', '0', '-1', '01', '1.5', '1e2', ' 1', '1 ', '1;process.exit()', '9007199254740992', 1]) {
  test(`rejects direct manual selector ${JSON.stringify(pullNumber)} before accessing GitHub`, async () => {
    const { args } = fixture();
    args.context.eventName = 'workflow_dispatch';
    args.mode = 'manual';
    args.pullNumber = pullNumber;
    args.github = new Proxy({}, { get() { assert.fail('GitHub accessed before selector validation'); } });
    await assert.rejects(run(args), /manual PR refresh requires/);
  });
}
for (const mode of [undefined, '', 'all']) {
  test(`rejects invalid refresh mode ${JSON.stringify(mode)} before accessing GitHub`, async () => {
    const { args } = fixture();
    args.mode = mode;
    args.github = new Proxy({}, { get() { assert.fail('GitHub accessed before mode validation'); } });
    await assert.rejects(run(args), /invalid PR refresh mode/);
  });
}
test('manual refresh cannot run on a push', async () => {
  const { args } = fixture();
  args.mode = 'manual';
  args.pullNumber = '1';
  args.github = new Proxy({}, { get() { assert.fail('GitHub accessed on manual push'); } });
  await assert.rejects(run(args), /manual PR refresh requires/);
});
for (const inputs of [{}, { candidate_sha: 'candidate', candidate_ref: 'release/1.2.3' }, { pull_number: '99' }]) {
  test(`inherited dispatch stays automatic with caller inputs ${JSON.stringify(inputs)}`, async () => {
    const { args, calls } = fixture({ autoMerge: null });
    args.context.eventName = 'workflow_dispatch';
    args.context.payload = { inputs };
    await run(args);
    assert.equal(calls.lists.length, 1);
    assert.deepEqual(calls.reads, [1]);
    assert.deepEqual(calls.updates, []);
    assert.deepEqual(calls.failures, []);
  });
}
test('an inherited baseline dispatch can refresh auto-merge PRs without a manual selector', async () => {
  const { args, calls } = fixture();
  args.context.eventName = 'workflow_dispatch';
  await run(args);
  assert.equal(calls.updates.length, 1);
});
test('automatic pushes leave manual PRs untouched', async () => {
  const { args, calls } = fixture({ autoMerge: null });
  await run(args);
  assert.deepEqual(calls.comparisons, []);
  assert.deepEqual(calls.updates, []);
  assert.deepEqual(calls.logs, ['#1: awaiting explicit refresh']);
});
test('automatic eligibility uses freshly read auto-merge state rather than the list snapshot', async () => {
  for (const [listed, fresh, expected] of [[null, {}, 1], [{}, null, 0]]) {
    const { args, calls } = fixture({ autoMerge: listed });
    const get = args.github.rest.pulls.get;
    args.github.rest.pulls.get = async (options) => {
      const result = await get(options);
      result.data.auto_merge = fresh;
      return result;
    };
    await run(args);
    assert.equal(calls.updates.length, expected);
  }
});
test('revoking auto-merge during unknown-state retry stops the update', async () => {
  const { args, calls } = fixture({ mergeable: null });
  const get = args.github.rest.pulls.get;
  args.github.rest.pulls.get = async (options) => {
    const result = await get(options);
    if (calls.reads.length > 1) result.data.auto_merge = null;
    return result;
  };
  await run(args);
  assert.deepEqual(calls.sleeps, [5000]);
  assert.deepEqual(calls.updates, []);
  assert.deepEqual(calls.failures, []);
});
for (const [eventName, ref] of [
  ['pull_request', 'refs/heads/main'],
  ['pull_request_target', 'refs/heads/main'],
  ['workflow_run', 'refs/heads/main'],
  ['push', undefined],
  ['push', 'main'],
  ['push', 'refs/pull/1/merge'],
  ['push', 'refs/tags/v0.1.0'],
  ['workflow_dispatch', 'refs/heads/fix/untrusted'],
  ['push', 'refs/heads/release/01.2.3'],
  ['push', 'refs/heads/release/1.2.3-rc.1'],
  ['push', 'refs/heads/release/1.2.3/extra'],
]) {
  test(`rejects ${eventName} on ${ref} before accessing GitHub`, async () => {
    const { args } = fixture();
    args.context.eventName = eventName;
    args.context.ref = ref;
    args.github = new Proxy({}, { get() { assert.fail('GitHub accessed before context validation'); } });
    await assert.rejects(run(args), /PR updates require a push or dispatch/);
  });
}
test('retries unknown mergeability and then updates', async () => {
  const { args, calls } = fixture({ mergeable: [null, true] }); await run(args);
  assert.equal(calls.sleeps.length, 1); assert.equal(calls.updates.length, 1);
});
test('persistent unknown fails after bounded retries', async () => {
  const { args, calls } = fixture({ mergeable: null }); await run(args);
  assert.equal(calls.sleeps.length, 3); assert.equal(calls.failures.length, 1);
});
for (const [name, patch] of [
  ['closed', { state: 'closed' }],
  ['retargeted', { base: { ref: 'release/1.2.3' } }],
  ['fork', { head: { sha: 'head', repo: { full_name: 'other/repo' } } }],
]) {
  test(`explicit manual refresh rejects a freshly ${name} PR`, async () => {
    const { args, calls } = fixture({ autoMerge: null });
    args.mode = 'manual';
    args.pullNumber = '1';
    args.context.eventName = 'workflow_dispatch';
    const get = args.github.rest.pulls.get;
    args.github.rest.pulls.get = async (options) => ({ data: { ...(await get(options)).data, ...patch } });
    await run(args);
    assert.deepEqual(calls.comparisons, []);
    assert.deepEqual(calls.updates, []);
    assert.deepEqual(calls.logs, ['#1: ineligible']);
  });
}
for (const [name, mergeable, sleeps, failures] of [['conflicting', false, 0, 0], ['unknown', null, 3, 1]]) {
  test(`explicit manual refresh preserves ${name} mergeability handling`, async () => {
    const { args, calls } = fixture({ autoMerge: null, mergeable });
    args.mode = 'manual';
    args.pullNumber = '1';
    args.context.eventName = 'workflow_dispatch';
    await run(args);
    assert.deepEqual(calls.updates, []);
    assert.equal(calls.sleeps.length, sleeps);
    assert.equal(calls.failures.length, failures);
  });
}
test('unknown-state retry compares fresh head and base tips before requesting an update', async () => {
  const { args, calls } = fixture({ mergeable: [null, true] });
  const get = args.github.rest.pulls.get;
  args.github.rest.pulls.get = async (options) => {
    const result = await get(options);
    result.data.head = { ...result.data.head, sha: `head-${calls.reads.length}` };
    return result;
  };
  args.github.rest.git.getRef = async () => ({ data: { object: { sha: `base-${calls.reads.length}` } } });
  await run(args);
  assert.deepEqual(calls.comparisons, ['head-1...base-1', 'head-2...base-2']);
  assert.equal(calls.updates[0].expected_head_sha, 'head-2');
});
test('unknown-state retry stops when a concurrent refresh makes the branch current', async () => {
  const { args, calls } = fixture({ mergeable: null });
  args.github.rest.repos.compareCommitsWithBasehead = async () => ({ data: {
    ahead_by: calls.reads.length === 1 ? 1 : 0,
  } });
  await run(args);
  assert.deepEqual(calls.sleeps, [5000]);
  assert.deepEqual(calls.updates, []);
  assert.deepEqual(calls.failures, []);
  assert.deepEqual(calls.logs, ['#1: current']);
});
test('expected-head rejection stays unresolved without retrying against an unreviewed head', async () => {
  const { args, calls } = fixture();
  let requests = 0;
  args.github.request = async (_route, options) => {
    requests++;
    assert.equal(options.expected_head_sha, 'head');
    throw Object.assign(new Error('head changed during comparison'), { status: 422 });
  };
  await run(args);
  assert.equal(requests, 1);
  assert.deepEqual(calls.sleeps, []);
  assert.deepEqual(calls.failures, ['1 PR branch update(s) unresolved']);
  assert.deepEqual(calls.logs, ['#1: unresolved: head changed during comparison']);
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
test('an App authorization failure remains a failed update', async () => {
  const { args, calls } = fixture();
  args.github.request = async () => {
    throw Object.assign(new Error('Resource not accessible by integration'), { status: 403 });
  };
  await run(args);
  assert.deepEqual(calls.failures, ['1 PR branch update(s) unresolved']);
});
test('workflow-permission denial fails the job with the original diagnostic', async () => {
  const { args, calls } = fixture();
  const message = 'refusing to allow a GitHub App to create or update workflow `.github/workflows/x.yml` without `workflows` permission';
  args.github.request = async () => {
    throw Object.assign(new Error(message), { status: 403 });
  };
  await run(args);
  assert.equal(calls.updates.length, 0);
  assert.deepEqual(calls.failures, ['1 PR branch update(s) unresolved']);
  assert.deepEqual(calls.logs, [`#1: unresolved: ${message}`]);
});

test('leaves stale Dependabot branches to scheduled native rebasing', async () => {
  const { args, calls } = fixture({ user: { login: 'dependabot[bot]', id: 49699333 } });
  await run(args);
  assert.deepEqual(calls.updates, []);
  assert.deepEqual(calls.failures, []);
});
test('explicit manual refresh also leaves Dependabot to native rebasing', async () => {
  const { args, calls } = fixture({ autoMerge: null, user: { login: 'dependabot[bot]', id: 49699333 } });
  args.mode = 'manual';
  args.pullNumber = '1';
  args.context.eventName = 'workflow_dispatch';
  await run(args);
  assert.deepEqual(calls.updates, []);
  assert.deepEqual(calls.logs, ['#1: managed by scheduled Dependabot rebasing']);
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

 test("updates PRs against the release branch that triggered validation", async () => {
  const { args, calls } = fixture();
  args.context.ref = "refs/heads/release/0.1.0";
  const get = args.github.rest.pulls.get;
  args.github.rest.pulls.get = async (options) => {
    const result = await get(options);
    result.data.base.ref = "release/0.1.0";
    return result;
  };
  args.github.rest.git.getRef = async ({ ref }) => {
    assert.equal(ref, "heads/release/0.1.0");
    return { data: { object: { sha: "release-head" } } };
  };
  const paginate = args.github.paginate;
  args.github.paginate = async (method, options) => {
    assert.equal(options.base, "release/0.1.0");
    return paginate(method, options);
  };
  await run(args);
  assert.equal(calls.updates.length, 1);
 });
