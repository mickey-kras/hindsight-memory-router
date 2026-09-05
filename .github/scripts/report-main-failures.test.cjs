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

test('missing logs and job-level cancellation still create actionable occurrence', () => {
  const result = reportsForJob(run, { ...job, steps: [], conclusion: 'cancelled' }, '');
  assert.equal(result.length, 1);
  assert.match(result[0].body, /Job logs unavailable/);
});

test('only canonical main publish runs can write issues', () => {
  assert.equal(trustedRun(run, 'owner/repo', 'main'), true);
  for (const override of [{ event: 'pull_request' }, { head_branch: 'feature' },
    { head_repository: { full_name: 'attacker/repo' } }, { path: '.github/workflows/ci.yml' }]) {
    assert.equal(trustedRun({ ...run, ...override }, 'owner/repo', 'main'), false);
  }
});

test('evidence strips credentials, URL parameters, mentions and issue markers', () => {
  const text = clean('Bearer secret password=hunter2 https://user:pass@example.com/a?token=x @owner <!-- forged -->');
  for (const secret of ['Bearer secret', 'hunter2', 'user:pass', 'token=x', '@owner', '<!--']) {
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
