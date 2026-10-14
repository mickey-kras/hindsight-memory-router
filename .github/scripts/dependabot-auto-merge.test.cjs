const test = require('node:test');
const assert = require('node:assert/strict');
const { run, trustedPull, verifiedCommits, eligibleCommits, classifiedUpdate, ensureMainRun } = require('./dependabot-auto-merge.cjs');

const bot = { login: 'dependabot[bot]', id: 49699333 };
function message(types = ['version-update:semver-patch']) {
  return `Bump dependencies\n\n---\nupdated-dependencies:\n${types.map((type, i) =>
    `- dependency-name: package-${i}\n  dependency-type: direct:production${type ? `\n  update-type: ${type}` : ''}`
  ).join('\n')}\n...\nSigned-off-by: dependabot[bot] <support@github.com>`;
}
const commits = [{ sha: 'a'.repeat(40), author: bot,
  commit: { message: message(), verification: { verified: true } } }];
const owned = { enabled_by: { login: 'github-actions[bot]', id: 41898282 } };
const pull = {
  number: 1, node_id: 'PR_1', user: bot, state: 'open', draft: false,
  head: { sha: 'a'.repeat(40), ref: 'dependabot/npm_and_yarn/example-1.0.1', repo: { full_name: 'owner/repo' } },
  base: { ref: 'main' },
};

test('all commits must have verified Dependabot authors', () => {
  assert.equal(verifiedCommits(commits), true);
  assert.equal(verifiedCommits([]), false);
  assert.equal(verifiedCommits([
    ...commits,
    { author: { login: 'owner', id: 1 }, commit: { verification: { verified: true } } },
  ]), false);
  assert.equal(verifiedCommits([
    { author: bot, commit: { verification: { verified: false } } },
  ]), false);
});

test('requires exact bot identity, origin, base and non-draft state', () => {
  assert.ok(trustedPull(pull, 'owner/repo', 'main'));
  for (const change of [
    { user: { ...bot, id: 1 } }, { state: 'closed' }, { draft: true },
    { head: { ...pull.head, repo: { full_name: 'fork/repo' } } },
    { head: { ...pull.head, ref: 'feat/update' } }, { base: { ref: 'release' } },
  ]) assert.equal(trustedPull({ ...pull, ...change }, 'owner/repo', 'main'), false);
});

function harness({ pulls = [pull], afterLookup, commitErrorFor, runs = [], associated = [], event = 'schedule', updates = commits } = {}) {
  const commands = [], dispatches = [], warnings = [], failures = [], disabled = [];
  let reads = 0;
  const endpoints = Object.fromEntries([
    'getRepo', 'getBranch', 'getPull', 'listPulls', 'listCommits', 'associated', 'runs', 'dispatch',
  ].map(key => [key, { name: key }]));
  const github = {
    rest: {
      repos: {
        get: async () => ({ data: { default_branch: 'main' } }),
        getBranch: async () => ({ data: { commit: { sha: 'b'.repeat(40) } } }),
        listPullRequestsAssociatedWithCommit: endpoints.associated,
      },
      pulls: {
        get: async ({ pull_number }) => ({
          data: (++reads > 1 && afterLookup) || pulls.find(candidate => candidate.number === pull_number),
        }),
        list: endpoints.listPulls,
        listCommits: endpoints.listCommits,
      },
      actions: {
        listWorkflowRuns: endpoints.runs,
        createWorkflowDispatch: async input => dispatches.push(input),
      },
    },
    graphql: async (_query, variables) => disabled.push(variables.pullRequestId),
    paginate: async (endpoint, args) => {
      if (endpoint === endpoints.listPulls) return pulls;
      if (endpoint === endpoints.listCommits) {
        if (args.pull_number === commitErrorFor) throw new Error('unavailable');
        return updates;
      }
      if (endpoint === endpoints.associated) return associated;
      if (endpoint === endpoints.runs) return runs;
      throw new Error('Unexpected endpoint');
    },
  };
  const options = {
    github,
    context: {
      repo: { owner: 'owner', repo: 'repo' }, eventName: event, ref: 'refs/heads/main',
      payload: event === 'pull_request_target' ? { pull_request: pull } : {},
    },
    core: {
      info() {}, warning: text => warnings.push(text), setFailed: text => failures.push(text),
    },
    mainWorkflow: 'publish.yml',
    merge: (...args) => commands.push(args),
  };
  return { options, commands, dispatches, warnings, failures, disabled };
}

for (const event of ['pull_request_target', 'schedule', 'workflow_dispatch', 'workflow_call']) {
  test(`${event} queues classified signed patch/minor updates and matches the evaluated SHA`, async () => {
    const h = harness({ event });
    await run(h.options);
    assert.deepEqual(h.commands, [[
      'owner/repo', 1, ['--auto', '--squash', '--match-head-commit', pull.head.sha],
    ]]);
  });
}

test('a changed head cannot be queued', async () => {
  const h = harness({ afterLookup: { ...pull, head: { ...pull.head, sha: 'c'.repeat(40) } } });
  await run(h.options);
  assert.deepEqual(h.commands, []);
});

test('an existing auto-merge decision is preserved without redundant commands', async () => {
  const h = harness({
    pulls: [{ ...pull, auto_merge: owned }],
  });
  await run(h.options);
  assert.deepEqual(h.commands, []);
});

for (const event of ['pull_request_target', 'schedule', 'workflow_dispatch', 'workflow_call']) {
  for (const types of [
    ['version-update:semver-major'], [''],
    ['version-update:semver-patch', 'version-update:semver-major'],
    ['version-update:semver-minor', ''],
  ]) {
    test(`${event} rejects every major or unclassified group (${types.join(',')})`, async () => {
      const h = harness({ event, pulls: [{ ...pull, auto_merge: owned }],
        updates: [{ ...commits[0], commit: { ...commits[0].commit, message: message(types) } }] });
      await run(h.options);
      assert.deepEqual(h.commands, []);
      assert.deepEqual(h.disabled, ['PR_1']);
    });
  }
}

test('signed patch/minor group is accepted and every commit must be classified', async () => {
  const update = { ...commits[0], commit: { ...commits[0].commit,
    message: message(['version-update:semver-patch', 'version-update:semver-minor']) } };
  const h = harness({ updates: [update] });
  await run(h.options);
  assert.equal(h.commands.length, 1);
  assert.equal(eligibleCommits([{ ...commits[0], sha: 'd'.repeat(40),
    commit: { ...commits[0].commit, message: message(['version-update:semver-major']) } }, update], pull.head.sha), false);
  assert.equal(eligibleCommits([update], 'c'.repeat(40)), false);
});

test('metadata must be a single well formed document with a nonempty fully classified list', () => {
  for (const malformed of [
    '', 'title says patch', message().replace('---\n', '----\n'),
    message().replace('...\n', '....\n'), message() + '\n' + message(),
    '---\nupdated-dependencies: []\n...\n',
    '---\nupdated-dependencies: not-a-list\n...\n',
    message().replace('package-0', ''),
    message().replace('  update-type:', '  update-type: major\n  update-type:'),
    '---\nupdated-dependencies: [\n...\n',
    '---\nupdated-dependencies: [&dep {dependency-name: test, update-type: version-update:semver-patch}, *dep]\n...\n',
  ]) assert.equal(classifiedUpdate(malformed), false, malformed);
  assert.equal(classifiedUpdate(message(['version-update:semver-minor'])), true);
});

test('metadata lookup failure withdraws an automation-owned decision and fails the run', async () => {
  const h = harness({ pulls: [{ ...pull, auto_merge: owned }], commitErrorFor: 1 });
  await run(h.options);
  assert.deepEqual(h.commands, []);
  assert.deepEqual(h.disabled, ['PR_1']);
  assert.equal(h.failures.length, 1);
});

test('unsigned commits withdraw automation-owned auto-merge', async () => {
  const h = harness({ pulls: [{ ...pull, auto_merge: owned }],
    updates: [{ ...commits[0], commit: { ...commits[0].commit, verification: { verified: false } } }] });
  await run(h.options);
  assert.deepEqual(h.disabled, ['PR_1']);
});

test('human auto-merge is preserved even for major updates and lookalike bots', async () => {
  for (const enabled_by of [{ login: 'owner', id: 1 }, { login: 'github-actions[bot]', id: 1 }]) {
    const h = harness({ pulls: [{ ...pull, auto_merge: { enabled_by } }], commitErrorFor: 1 });
    await run(h.options);
    assert.deepEqual(h.commands, []);
    assert.deepEqual(h.disabled, []);
    assert.deepEqual(h.failures, []);
  }
});

test('head changes and a human takeover observed before disable preserve the current decision', async () => {
  for (const afterLookup of [
    { ...pull, auto_merge: owned, head: { ...pull.head, sha: 'c'.repeat(40) } },
    { ...pull, auto_merge: { enabled_by: { login: 'owner', id: 1 } } },
  ]) {
    const h = harness({ pulls: [{ ...pull, auto_merge: owned }], afterLookup,
      updates: [{ ...commits[0], commit: { ...commits[0].commit, message: '' } }] });
    await run(h.options);
    assert.deepEqual(h.commands, []);
    assert.deepEqual(h.disabled, []);
  }
});

test('an observed manual disable during evaluation is respected', async () => {
  const h = harness({ pulls: [{ ...pull, auto_merge: owned }],
    afterLookup: { ...pull, auto_merge: null } });
  await run(h.options);
  assert.deepEqual(h.commands, []);
  assert.deepEqual(h.disabled, []);
});

test('a failed PR does not prevent evaluation of the next PR', async () => {
  const h = harness({ pulls: [pull, { ...pull, number: 2 }], commitErrorFor: 1 });
  await run(h.options);
  assert.equal(h.commands[0][1], 2);
  assert.equal(h.failures.length, 1);
});

test('dispatch from a work branch cannot merge', async () => {
  const h = harness({ event: 'workflow_dispatch' });
  h.options.context.ref = 'refs/heads/feat/test';
  await assert.rejects(run(h.options), /default branch/);
  assert.deepEqual(h.commands, []);
});

const associated = [{
  ...pull, merged_at: '2026-09-04T00:00:00Z', merge_commit_sha: 'b'.repeat(40),
}];

test('dispatches missing main validation only after a confirmed Dependabot merge', async () => {
  const h = harness({ associated });
  await ensureMainRun({ ...h.options, branch: 'main' });
  assert.deepEqual(h.dispatches, [
    { owner: 'owner', repo: 'repo', workflow_id: 'publish.yml', ref: 'main' },
  ]);
  const noMerge = harness();
  await ensureMainRun({ ...noMerge.options, branch: 'main' });
  assert.deepEqual(noMerge.dispatches, []);
});

test('closed Dependabot merge dispatches missing main validation', async () => {
  const closed = { ...pull, state: 'closed' };
  const h = harness({
    event: 'pull_request_target',
    pulls: [closed],
    associated: [{
      ...closed, merged_at: '2026-09-08T00:00:00Z', merge_commit_sha: 'b'.repeat(40),
    }],
  });
  h.options.context.payload.pull_request = closed;
  await run(h.options);
  assert.deepEqual(h.commands, []);
  assert.deepEqual(h.dispatches, [
    { owner: 'owner', repo: 'repo', workflow_id: 'publish.yml', ref: 'main' },
  ]);
});

for (const conclusion of [null, 'success', 'failure']) {
  test(`does not duplicate existing main run (${conclusion})`, async () => {
    const h = harness({
      associated,
      runs: [{ head_sha: 'b'.repeat(40), event: 'workflow_dispatch', conclusion }],
    });
    await ensureMainRun({ ...h.options, branch: 'main' });
    assert.deepEqual(h.dispatches, []);
  });
}
