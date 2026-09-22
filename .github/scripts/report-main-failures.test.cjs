const { test } = require('node:test');
const assert = require('node:assert/strict');
const { reportsForJob, trustedRun, clean, main } = require('./report-main-failures.cjs');
const { mkdtempSync, writeFileSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { spawnSync } = require('node:child_process');

const run = { id: 42, run_attempt: 1, head_sha: 'abc', head_branch: 'main', event: 'push',
  repository: { full_name: 'owner/repo' }, head_repository: { full_name: 'owner/repo' },
  path: '.github/workflows/publish.yml', html_url: 'https://github.com/owner/repo/actions/runs/42' };
const step = { name: 'smoke', number: 2, conclusion: 'failure',
  started_at: '2026-09-05T00:00:00Z', completed_at: '2026-09-05T00:00:03Z' };
const job = { id: 7, name: 'publish', conclusion: 'failure', steps: [step], html_url: 'https://github.com/job/7' };
const log = text => `2026-09-05T00:00:01.000Z ${text}`;

test('same exact error reuses signature across runs, different error does not', () => {
  const first = reportsForJob(run, job, log('ValueError: invalid bank'))[0];
  const repeated = reportsForJob({ ...run, id: 50 }, job, log('ValueError: invalid bank'))[0];
  const different = reportsForJob(run, job, log('ValueError: missing scope'))[0];
  assert.equal(first.key, repeated.key);
  assert.notEqual(first.occurrence, repeated.occurrence);
  assert.notEqual(first.key, different.key);
});

test('exit-only failures are isolated by run and attempt', () => {
  const text = log('##[error]Process completed with exit code 1.');
  const first = reportsForJob(run, job, text)[0];
  assert.notEqual(first.key, reportsForJob({ ...run, id: 43 }, job, text)[0].key);
  assert.notEqual(first.key, reportsForJob({ ...run, run_attempt: 2 }, { ...job, id: 8 }, text)[0].key);
  assert.match(first.body, /No reliable error signature/);
});

test('independent failed tests produce independent issues', () => {
  const text = [log('FAILED tests/test_x.py::test_a - AssertionError: 200 != 403'),
    log('FAILED tests/test_x.py::test_b - ValueError: invalid bank')].join('\n');
  assert.equal(reportsForJob(run, job, text).length, 2);
});

test('passed steps and shell command echoes cannot supply the failure signature', () => {
  const text = '2026-09-04T23:59:59Z ValueError: unrelated\n' + log('echo ValueError: not an error');
  assert.match(reportsForJob(run, job, text)[0].body, /No reliable error signature/);
});

test('smoke assertion groups on backend, check and exact message', () => {
  const smoke = storage => log('HMR_FAILURE_JSON=' + JSON.stringify({ mode: 'fake', storage,
    check: 'readiness', message: 'expected HTTP 200; actual HTTP 503' }));
  assert.notEqual(reportsForJob(run, job, smoke('sqlite'))[0].key,
    reportsForJob(run, job, smoke('postgres'))[0].key);
});

test('a known smoke assertion does not hide another backend startup failure', () => {
  const smoke = (storage, message) => log('HMR_FAILURE_JSON=' + JSON.stringify({ mode: 'fake',
    storage, check: 'readiness', message }));
  const text = [smoke('sqlite', 'HTTP 503'), smoke('postgres', '')].join('\n');
  const reports = reportsForJob(run, job, text);
  assert.equal(reports.length, 2);
  const next = reportsForJob({ ...run, id: 43 }, job, text);
  assert.equal(reports[0].key, next[0].key);
  assert.notEqual(reports[1].key, next[1].key);
  assert.match(reports[1].body, /No reliable error signature/);
});

test('cancelled runs and non-failing jobs never produce reports', () => {
  assert.deepEqual(reportsForJob({ ...run, conclusion: 'cancelled' }, job, log('ValueError: invalid')), []);
  for (const conclusion of ['cancelled', 'skipped', 'success', 'neutral', null]) {
    assert.deepEqual(reportsForJob(run, { ...job, conclusion }, log('ValueError: invalid')), []);
  }
});

test('real job failures remain actionable without failed steps or logs', () => {
  for (const conclusion of ['failure', 'timed_out', 'action_required', 'startup_failure']) {
    const result = reportsForJob(run, { ...job, steps: [], conclusion }, '');
    assert.equal(result.length, 1);
    assert.match(result[0].body, /Job logs unavailable/);
    assert.ok(result[0].body.includes(`- Conclusion: ${conclusion}`));
  }
});

test('a cancelled run exits before fetching jobs, logs or issues', () => {
  const execute = (command, args) => {
    assert.equal(command, 'gh');
    if (args[1].endsWith('/actions/runs/42')) return JSON.stringify({ ...run, conclusion: 'cancelled' });
    if (args[1] === '/repos/owner/repo') return JSON.stringify({ default_branch: 'main' });
    throw new Error(`Unexpected API: ${args[1]}`);
  };
  assert.deepEqual(main({ GITHUB_REPOSITORY: 'owner/repo', GITHUB_RUN_ID: '42' }, execute), []);
});

test('a failed workflow reports real errors without downloading cancelled or skipped jobs', () => {
  const execute = (command, args) => {
    if (command === 'bash') return '';
    const path = args[1];
    if (path.endsWith('/actions/runs/42')) return JSON.stringify({ ...run, conclusion: 'failure' });
    if (path === '/repos/owner/repo') return JSON.stringify({ default_branch: 'main' });
    if (path.includes('/jobs?')) return JSON.stringify([{ jobs: [job,
      { ...job, id: 8, conclusion: 'cancelled' }, { ...job, id: 9, conclusion: 'skipped' }] }]);
    if (path.includes('/issues?')) return JSON.stringify([[]]);
    if (path === '/repos/owner/repo/actions/jobs/7/logs') return log('ValueError: invalid bank');
    throw new Error(`Unexpected API: ${path}`);
  };
  const reports = main({ GITHUB_REPOSITORY: 'owner/repo', GITHUB_RUN_ID: '42' }, execute);
  assert.equal(reports.length, 1);
  assert.match(reports[0].body, /ValueError: invalid bank/);
});

test('cancellation during log collection prevents pending issue writes', () => {
  let reads = 0;
  const execute = (command, args) => {
    assert.equal(command, 'gh');
    const path = args[1];
    if (path.endsWith('/actions/runs/42')) return JSON.stringify({ ...run,
      conclusion: reads++ ? 'cancelled' : null });
    if (path === '/repos/owner/repo') return JSON.stringify({ default_branch: 'main' });
    if (path.includes('/jobs?')) return JSON.stringify([{ jobs: [job] }]);
    if (path.includes('/issues?')) return JSON.stringify([[]]);
    if (path.endsWith('/logs')) return log('ValueError: invalid bank');
    throw new Error(`Unexpected API: ${path}`);
  };
  assert.deepEqual(main({ GITHUB_REPOSITORY: 'owner/repo', GITHUB_RUN_ID: '42' }, execute), []);
});

test('log download is retried and late-arriving logs supply the real excerpt', () => {
  let downloads = 0;
  const sleeps = [];
  const execute = (command, args) => {
    if (command === 'bash') return '';
    const path = args[1];
    if (path.endsWith('/actions/runs/42')) return JSON.stringify(run);
    if (path === '/repos/owner/repo') return JSON.stringify({ default_branch: 'main' });
    if (path.includes('/jobs?')) return JSON.stringify([{ jobs: [job] }]);
    if (path.includes('/issues?')) return JSON.stringify([[]]);
    if (path.endsWith('/logs')) {
      downloads += 1;
      if (downloads < 3) throw new Error('Command failed: gh api\nHTTP 404: logs not yet available');
      assert.ok(args.includes('--allow-escape-sequences'));
      return log('\x1b[31mValueError: unknown blob\x1b[0m');
    }
    throw new Error(`Unexpected API: ${path}`);
  };
  const reports = main({ GITHUB_REPOSITORY: 'owner/repo', GITHUB_RUN_ID: '42' }, execute, ms => sleeps.push(ms));
  assert.equal(downloads, 3);
  assert.deepEqual(sleeps, [10000, 20000]);
  assert.match(reports[0].body, /ValueError: unknown blob/);
  assert.doesNotMatch(reports[0].body, /Job logs unavailable/);
});

test('unavailable logs fall back to failed steps, check annotations, and the download error', () => {
  const sleeps = [];
  const failing = { ...job, check_run_url: 'https://api.github.com/repos/owner/repo/check-runs/7' };
  const execute = (command, args) => {
    if (command === 'bash') return '';
    const path = args[1];
    if (path.endsWith('/actions/runs/42')) return JSON.stringify(run);
    if (path === '/repos/owner/repo') return JSON.stringify({ default_branch: 'main' });
    if (path.includes('/jobs?')) return JSON.stringify([{ jobs: [failing] }]);
    if (path.includes('/issues?')) return JSON.stringify([[]]);
    if (path.endsWith('/logs')) throw new Error('Command failed: gh api\nHTTP 404: logs not yet available');
    if (path.endsWith('/annotations?per_page=100')) return JSON.stringify([
      { annotation_level: 'failure', message: 'Process completed with exit code 1.' },
      { annotation_level: 'notice', message: 'ubuntu-latest label migration notice' }]);
    throw new Error(`Unexpected API: ${path}`);
  };
  const reports = main({ GITHUB_REPOSITORY: 'owner/repo', GITHUB_RUN_ID: '42' }, execute, ms => sleeps.push(ms));
  assert.deepEqual(sleeps, [10000, 20000]);
  assert.match(reports[0].body, /Step "smoke" concluded failure\./);
  assert.match(reports[0].body, /Process completed with exit code 1\./);
  assert.match(reports[0].body, /Job log download failed: HTTP 404/);
  assert.doesNotMatch(reports[0].body, /migration notice/);
  assert.doesNotMatch(reports[0].body, /Job logs unavailable/);
});

test('only canonical main publish runs can write issues', () => {
  assert.equal(trustedRun(run, 'owner/repo', 'main'), true);
  for (const override of [{ event: 'pull_request' }, { head_branch: 'feature' },
    { head_repository: { full_name: 'attacker/repo' } }, { path: '.github/workflows/ci.yml' }]) {
    assert.equal(trustedRun({ ...run, ...override }, 'owner/repo', 'main'), false);
  }
});

test('evidence strips terminal controls, credentials, URL parameters, mentions and issue markers', () => {
  const text = clean('\x1b[31mBearer secret\x1b[0m password=hunter2 https://user:pass@example.com/a?token=x @owner <!-- forged -->' +
    '\x1b]8;;https://example.com?token=hidden\x07link\x1b]8;;\x07');
  for (const secret of ['\x1b', '\x07', 'hidden', 'Bearer secret', 'hunter2', 'user:pass', 'token=x', '@owner', '<!--']) {
    assert.ok(!text.includes(secret));
  }
});

test('completed Sonar findings prevent a generic duplicate for the gate', () => {
  const sonarJob = { ...job, steps: [{ ...step, name: 'SonarQube quality gate' }] };
  const execute = (command, args) => {
    assert.equal(command, 'gh');
    const path = args[1];
    if (path.endsWith('/actions/runs/42')) return JSON.stringify(run);
    if (path === '/repos/owner/repo') return JSON.stringify({ default_branch: 'main' });
    if (path.includes('/jobs?')) return JSON.stringify([{ jobs: [sonarJob] }]);
    if (path.includes('/issues?')) return JSON.stringify([[{ body: `<!-- sonar-finding:issue-x -->\n- Detected at commit: \`abc\`\n- Workflow: ${run.html_url}` }]]);
    if (path.endsWith('/logs')) return log('##[error]Process completed with exit code 1.');
    throw new Error(`Unexpected API: ${path}`);
  };
  assert.deepEqual(main({ GITHUB_REPOSITORY: 'owner/repo', GITHUB_RUN_ID: '42' }, execute), []);
});

test('issue upsert preserves history, reopens new occurrences, and deduplicates retries', () => {
  const directory = mkdtempSync(join(tmpdir(), 'report-test-'));
  try {
    const calls = join(directory, 'calls');
    writeFileSync(join(directory, 'body.md'), 'new diagnostic');
    writeFileSync(join(directory, 'gh'), `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.CALLS, JSON.stringify(args)+'\\n');
if(args[0]==='issue' && args[1]==='list') console.log(JSON.stringify([{number:171,state:'CLOSED',body:'<!-- main-failure:v2-test -->\\noriginal diagnostic'}]));
if(args[0]==='api') console.log(JSON.stringify([[{body:process.env.REPEATED==='yes'?'<!-- main-occurrence:run-1 -->':''}]]));
`, { mode: 0o755 });
    const invoke = repeated => spawnSync('bash', [resolve(__dirname, 'upsert-main-failure-issue.sh'), join(directory, 'body.md')], {
      encoding: 'utf8', env: { ...process.env, PATH: `${directory}:${process.env.PATH}`,
        CALLS: calls, REPEATED: repeated, GITHUB_REPOSITORY: 'owner/repo', GITHUB_REPOSITORY_OWNER: 'owner',
        FAILURE_KEY: 'v2-test', FAILURE_TITLE: 'failure', FAILURE_OCCURRENCE: 'run-1' },
    });
    assert.equal(invoke('no').status, 0);
    let recorded = readFileSync(calls, 'utf8');
    assert.match(recorded, /"issue","reopen","171"/);
    assert.match(recorded, /"issue","comment","171"/);
    assert.doesNotMatch(recorded, /"issue","edit"/);
    writeFileSync(calls, '');
    assert.equal(invoke('yes').status, 0);
    recorded = readFileSync(calls, 'utf8');
    assert.doesNotMatch(recorded, /"issue","(?:comment|reopen|edit|create)"/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('startup command failure dumps container logs before cleanup and retains exit code', () => {
  const smoke = readFileSync(resolve(__dirname, '../../tests/integration/smoke.sh'), 'utf8');
  const functions = smoke.slice(smoke.indexOf('begin_check()'), smoke.indexOf('run_check "generate disposable'));
  // Only the function/trap section runs; Docker is replaced with a recording stub.
  const script = `set -euo pipefail
mode=fake; router_db=postgres; project=test; compose_file=test
checks_total=0; checks_passed=0; current_check=startup; failure_message=''
tmp_dir=$(mktemp -d)
docker() { echo "DOCKER $*" >&2; }
${functions}
cleanup() { echo CLEANUP >&2; rm -rf "$tmp_dir"; }
run_check 'start compose stack' bash -c 'exit 3'
`;
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8' });
  assert.equal(result.status, 3);
  assert.match(result.stderr, /HMR_FAILURE_JSON=.*start compose stack/);
  assert.ok(result.stderr.indexOf('logs --no-color') < result.stderr.indexOf('CLEANUP'));
});

test('captures fractional timestamps in the final step second', () => {
  const text = '2026-09-05T00:00:03.900Z #225: unresolved: missing workflows permission';
  const first = reportsForJob(run, job, text)[0];
  assert.match(first.body, /#225: unresolved: missing workflows permission/);
  assert.equal(first.key, reportsForJob({ ...run, id: 43 }, job, text)[0].key);
  assert.doesNotMatch(first.body, /diagnostics incomplete/);
});

 test('reports release pushes only through the protected release workflow', () => {
  const release = { ...run, head_branch: 'release/0.1.0', path: '.github/workflows/release.yml' };
  assert.equal(trustedRun(release, 'owner/repo', 'main'), true);
  assert.equal(trustedRun({ ...release, event: 'pull_request' }, 'owner/repo', 'main'), false);
  assert.equal(trustedRun({ ...release, path: '.github/workflows/other.yml' }, 'owner/repo', 'main'), false);
 });
