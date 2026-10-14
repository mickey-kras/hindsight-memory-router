const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, dirname } = require('node:path');
const test = require('node:test');
const { classify, full, impact, parseDiff } = require('./ci-impact.cjs');

const source = readFileSync(join(__dirname, 'ci-impact.cjs'), 'utf8');
const workflow = readFileSync(join(__dirname, '../workflows/ci.yml'), 'utf8');
const wrapper = workflow.split('          script: |\n')[1].split('\n  hindsight:')[0]
  .split('\n').map(line => line.slice(12)).join('\n');

function repository(fn) {
  const directory = mkdtempSync(join(tmpdir(), 'ci-impact-test-'));
  const git = args => execFileSync('git', args, { cwd: directory, stdio: ['pipe', 'pipe', 'pipe'] });
  const put = (path, content) => {
    mkdirSync(dirname(join(directory, path)), { recursive: true });
    writeFileSync(join(directory, path), content);
  };
  const commit = () => {
    git(['add', '-A']);
    git(['commit', '-qm', 'fixture']);
    return git(['rev-parse', 'HEAD']).toString().trim();
  };
  git(['init', '-q']);
  git(['config', 'user.email', 'ci@example.invalid']);
  git(['config', 'user.name', 'CI fixture']);
  try { return fn({ directory, git, put, commit }); }
  finally { rmSync(directory, { recursive: true, force: true }); }
}

test('source dependencies include runtime crypto closure, API and shared UI types', () => {
  for (const path of ['memory_router/envelope.py', 'memory_router/key_wrap.py',
    'memory_router/canonical.py', 'memory_router/errors.py', 'memory_router/__init__.py',
    'memory_router/admin.py', 'openapi/openapi.json', 'openapi/openclaw.json', 'ui/src/lib/types.ts']) {
    assert.deepEqual(classify([path]), { python: true, ui: true, release: false }, path);
  }
  for (const path of ['ui/src/App.tsx', 'ui/tests/gen_fixtures.py', 'ui/tests/e2e/console.spec.ts']) {
    assert.deepEqual(classify([path]), { python: false, ui: true, release: false }, path);
  }
  assert.deepEqual(classify(['tests/test_envelope_validation.py']), { python: true, ui: false, release: false });
  assert.deepEqual(classify(['ui/src/App.tsx', 'tests/test_admin.py']), { python: true, ui: true, release: false });
});

test('only known documentation inputs have no affected workers', () => {
  for (const path of ['README.md', 'SECURITY.md', 'docs/OPENAPI.md',
    'docs/security/quarantine.md', 'docs/architecture/generated/Recall.svg']) {
    assert.deepEqual(classify([path]), { python: false, ui: false, release: false }, path);
  }
  for (const path of ['THIRD_PARTY_NOTICES.md', 'ui/README.md', 'docs/docker-compose.swagger.yml',
    'docs/architecture/workspace.dsl', 'new/path.md']) assert.deepEqual(classify([path]), full(), path);
});

test('repository-wide artifact guard remains required beneath every allowlisted source boundary', () => repository(({ directory, git, put }) => {
  const guard = join(__dirname, 'check-tracked-artifacts.py');
  const cacheNames = JSON.parse(execFileSync('python3', ['-c',
    "import json, runpy, sys; print(json.dumps(sorted(runpy.run_path(sys.argv[1])['CACHE_NAMES'])))", guard],
  { encoding: 'utf8' }));
  const paths = [];
  for (const name of [...cacheNames, 'pkg.egg-info']) {
    for (const [prefix, filename] of [['docs', 'note.md'], ['ui/src', 'note.ts'],
      ['ui/tests', 'fixture.py'], ['memory_router', 'module.py'], ['tests', 'test_note.py']]) {
      const path = `${prefix}/${name}/${filename}`;
      paths.push(path);
      put(path, 'tracked artifact\n');
      assert.deepEqual(classify([path]), full(), path);
    }
  }
  git(['add', '-A']);
  const rejected = spawnSync('python3', [guard], { cwd: directory, encoding: 'utf8' });
  assert.equal(rejected.status, 1, rejected.stderr);
  for (const path of paths) assert.ok(rejected.stderr.includes(path), path);
}));

test('artifact names are exact path components, not similarly named documentation', () => repository(({ directory, git, put }) => {
  for (const path of ['docs/.mypy_cache.md', 'docs/.pytest_cache-example/readme.md',
    'docs/.ruff_cache-guide.md', 'docs/__pycache__-guide.md', 'docs/pkg.egg-info.md',
    'docs/pkg.egg-info-sources/readme.md']) {
    put(path, 'source documentation\n');
    assert.deepEqual(classify([path]), { python: false, ui: false, release: false }, path);
  }
  git(['add', '-A']);
  const accepted = spawnSync('python3', [join(__dirname, 'check-tracked-artifacts.py')],
    { cwd: directory, encoding: 'utf8' });
  assert.equal(accepted.status, 0, accepted.stderr);
}));

test('artifact guard dependencies survive both real Git rename endpoints', () => repository(({ directory, git, put, commit }) => {
  put('docs/guide.md', 'same content\n');
  const baseSha = commit();
  mkdirSync(join(directory, 'ui/src/__pycache__'), { recursive: true });
  git(['mv', 'docs/guide.md', 'ui/src/__pycache__/note.ts']);
  const artifactSha = commit();
  const options = { eventName: 'pull_request', baseSha, headSha: artifactSha };
  assert.deepEqual(impact(options, git), full(), 'new artifact endpoint forces the global guard');
  git(['mv', 'ui/src/__pycache__/note.ts', 'docs/restored.md']);
  const headSha = commit();
  assert.deepEqual(impact({ ...options, baseSha: artifactSha, headSha }, git), full(),
    'old artifact endpoint remains part of the complete dependency diff');
}));

test('workflow, toolchain, package, lock, build, release and unknown inputs force full', () => {
  for (const path of ['.github/workflows/ci.yml', '.github/scripts/ci-impact.cjs',
    '.github/scripts/release.cjs', '.github/scripts/package-lock.json', 'build-requirements.txt',
    'requirements.txt', 'dev-requirements.txt', 'pyproject.toml', 'package-lock.json', 'package.json',
    'ui/package-lock.json', 'ui/package.json', 'ui/tsconfig.json', 'ui/vite.config.ts',
    'ui/src/new.lock', 'ui/src/tsconfig.json', 'ui/tests/pytest.ini', 'tests/requirements.txt',
    'tests/integration/smoke.sh', 'tests/integration/python-build.sh', 'tests/unknown.json',
    'Dockerfile', '.dockerignore', 'compose.yaml',
    'MANIFEST.in', 'LICENSE', 'licenses/UNICODE-3.0.txt', 'compat/hindsight.json',
    'compat/openclaw.json', 'release-version.json', 'scripts/check_openclaw_compat.py',
    '.gitleaks.toml', '.semgrep.yml', '.node-version', 'redocly.yaml', 'new-package/file.ts']) {
    assert.deepEqual(classify(['README.md', path]), full(), path);
  }
  assert.deepEqual(classify([]), full());
});

test('raw complete diff parses both rename endpoints and deletions', () => {
  assert.deepEqual(parseDiff(Buffer.from('R100\0ui/src/old.ts\0memory_router/new.py\0D\0openapi/deleted.json\0')),
    ['ui/src/old.ts', 'memory_router/new.py', 'openapi/deleted.json']);
  for (const value of ['', 'M\0README.md', 'R100\0README.md\0', 'M\0',
    'T\0README.md\0', 'U\0README.md\0', 'C100\0README.md\0docs/copy.md\0',
    'M\0../README.md\0', 'M\0docs//x.md\0', 'M\0docs/x\ny.md\0', 'M\0/docs/x.md\0']) {
    assert.throws(() => parseDiff(Buffer.from(value)), value);
  }
  assert.throws(() => parseDiff(Buffer.from([77, 0, 255, 0])));
});

test('real Git history handles cross-boundary renames, deletion, and diverged bases', () => repository(({ git, put, commit }) => {
  put('memory_router/crypto.py', 'source\n');
  put('README.md', 'readme\n');
  put('docs/guide.md', 'guide\n');
  const base = commit();
  git(['checkout', '-qb', 'topic']);
  git(['mv', 'memory_router/crypto.py', 'docs/runtime.md']);
  let head = commit();
  const options = { eventName: 'pull_request', baseSha: base, headSha: head };
  assert.deepEqual(impact(options, git), { python: true, ui: true, release: false },
    'rename into allowlisted docs still includes old runtime');
  git(['reset', '--hard', base]);
  put('ui/src/placeholder.ts', 'placeholder');
  git(['mv', 'docs/guide.md', 'ui/src/Widget.tsx']);
  head = commit();
  assert.deepEqual(impact({ ...options, headSha: head }, git), { python: false, ui: true, release: false },
    'rename out of docs includes the new UI dependency');
  git(['reset', '--hard', base]);
  git(['rm', 'memory_router/crypto.py']);
  head = commit();
  assert.deepEqual(impact({ ...options, headSha: head }, git), { python: true, ui: true, release: false });
  git(['reset', '--hard', base]);
  put('docs/guide.md', 'changed docs\n');
  head = commit();
  git(['checkout', '--detach', base]);
  put('unrelated-base-config', 'base advanced\n');
  const advancedBase = commit();
  assert.deepEqual(impact({ ...options, baseSha: advancedBase, headSha: head }, git),
    { python: false, ui: false, release: false }, 'PR three-dot diff excludes unrelated base changes');
}));

test('diffs larger than REST file ceilings are complete', () => repository(({ git, put, commit }) => {
  put('README.md', 'baseline');
  const baseSha = commit();
  for (let index = 0; index < 3001; index += 1) put(`docs/item-${index}.md`, 'docs');
  put('zzz-unclassified', 'must not be lost beyond an API page/ceiling');
  const headSha = commit();
  assert.deepEqual(impact({ eventName: 'pull_request', baseSha, headSha }, git), full());
}));

test('missing history, shallow history, ambiguity, malformed and truncated diff fail closed', () => {
  const options = { eventName: 'pull_request', baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40) };
  const git = args => Buffer.from(args[0] === 'rev-parse' ? 'false\n' :
    args[0] === 'merge-base' ? 'c'.repeat(40) + '\n' : args[0] === 'diff' ? 'M\0README.md\0' : '');
  assert.deepEqual(impact(options, git), { python: false, ui: false, release: false });
  for (const command of ['rev-parse', 'cat-file', 'merge-base', 'diff']) {
    assert.deepEqual(impact(options, args => {
      if (args[0] === command) throw new Error('Git failed, timed out or exceeded maxBuffer');
      return git(args);
    }), full());
  }
  for (const [command, output] of [['rev-parse', 'true'], ['merge-base', ''],
    ['merge-base', `${'c'.repeat(40)}\n${'d'.repeat(40)}`], ['diff', 'M\0README.md'], ['diff', '']]) {
    assert.deepEqual(impact(options, args => args[0] === command ? Buffer.from(output) : git(args)), full());
  }
  for (const changes of [{ baseSha: '--unsafe' }, { headSha: '' }]) assert.deepEqual(impact({ ...options, ...changes }, git), full());
});

test('candidate SHA, candidate ref and every non-PR event bypass classification', () => {
  for (const changes of [{ eventName: 'push' }, { eventName: 'workflow_dispatch' },
    { candidateSha: 'a'.repeat(40) }, { candidateRef: 'refs/heads/release/1' }]) {
    assert.deepEqual(impact({ eventName: 'pull_request', ...changes }, () => assert.fail('must not read diff')), full());
  }
});

function runWrapper(directory, baseSha, headSha, extra = {}) {
  const driver = `const values = JSON.parse(process.argv[1]);
    const output = {}; const core = { setOutput: (k,v) => output[k] = v, info() {}, warning() {} };
    const context = {eventName: values.eventName || 'pull_request', payload: {pull_request: {
      base: {sha: values.baseSha}, head: {sha: values.headSha}}}};
    const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
    new AsyncFunction('require', 'context', 'core', values.script)(require, context, core)
      .then(() => process.stdout.write(JSON.stringify(output))).catch(e => {console.error(e);process.exit(1)});`;
  return JSON.parse(execFileSync(process.execPath, ['-e', driver, JSON.stringify({ script: wrapper, baseSha, headSha, ...extra })], {
    cwd: directory, env: { ...process.env, RUNNER_TEMP: directory, CANDIDATE_SHA: '', CANDIDATE_REF: '', ...extra },
    stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8',
  }));
}

test('actual workflow uses trusted base classifier and forces full for classifier edits', () => repository(({ directory, put, commit }) => {
  put('.github/scripts/ci-impact.cjs', source);
  put('README.md', 'baseline');
  const base = commit();
  put('README.md', 'doc edit');
  let head = commit();
  assert.deepEqual(runWrapper(directory, base, head), { python: 'false', ui: 'false', release: 'false' });
  put('.github/scripts/ci-impact.cjs', "require('node:fs').writeFileSync('untrusted-executed', 'bad'); module.exports.impact=()=>({python:false,ui:false,release:false});");
  head = commit();
  assert.deepEqual(runWrapper(directory, base, head), { python: 'true', ui: 'true', release: 'true' });
  assert.equal(existsSync(join(directory, 'untrusted-executed')), false);
  for (const extra of [{ eventName: 'push' }, { CANDIDATE_SHA: base }, { CANDIDATE_REF: 'release/1' }]) {
    assert.deepEqual(runWrapper(directory, base, head, extra), { python: 'true', ui: 'true', release: 'true' });
  }
}));

test('actual workflow defaults full for bootstrap, classifier errors and invalid outputs', () => repository(({ directory, put, commit }) => {
  put('README.md', 'baseline');
  let base = commit();
  assert.deepEqual(runWrapper(directory, base, base), { python: 'true', ui: 'true', release: 'true' });
  for (const code of ["throw new Error('classifier failure')", 'module.exports.impact=()=>null',
    'module.exports.impact=()=>({python:false,ui:false})',
    'module.exports.impact=()=>({python:"false",ui:false,release:false})']) {
    put('.github/scripts/ci-impact.cjs', code);
    base = commit();
    assert.deepEqual(runWrapper(directory, base, base), { python: 'true', ui: 'true', release: 'true' });
  }
}));
