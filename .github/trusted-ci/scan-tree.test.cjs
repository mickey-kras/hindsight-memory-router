const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { prepare, prepareAudits } = require('./scan-tree.cjs');

function fixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'router-scan-'));
  const candidate = path.join(root, 'candidate');
  const trusted = path.join(root, 'trusted');
  const scan = path.join(root, 'scan');
  const audits = path.join(root, 'audits');
  const write = (directory, name, content) => {
    const file = path.join(directory, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
  };
  fs.mkdirSync(candidate);
  write(trusted, '.aislop/config.yml', 'ci:\n  failBelow: 100\n');
  write(trusted, 'pyproject.toml', '[tool.ruff]\nline-length = 100\n');
  try { run({ root, candidate, trusted, scan, audits, write }); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test('candidate scanner configuration cannot suppress source findings', () => fixture((f) => {
  for (const name of ['.aislop/config.yml', '.aislopignore', '.gitignore', '.semgrepignore',
    '.gitleaks.toml', '.gitleaksignore', 'pyproject.toml', 'nested/pyproject.toml',
    'nested/.ruff.toml', '.npmrc', 'nested/biome.json', 'eslint.config.js']) {
    f.write(f.candidate, name, 'ignore everything');
  }
  f.write(f.candidate, 'src/example.py', 'eval(user_input)\n');
  prepare(f.candidate, f.scan, f.trusted);
  assert.equal(fs.readFileSync(path.join(f.scan, 'src/example.py'), 'utf8'), 'eval(user_input)\n');
  assert.equal(fs.readFileSync(path.join(f.scan, '.aislop/config.yml'), 'utf8'), 'ci:\n  failBelow: 100\n');
  assert.equal(fs.readFileSync(path.join(f.scan, 'pyproject.toml'), 'utf8'), '[tool.ruff]\nline-length = 100\n');
  for (const name of ['.semgrepignore', '.gitignore', '.gitleaks.toml', 'nested/pyproject.toml',
    'nested/.ruff.toml', '.npmrc', 'nested/biome.json', 'eslint.config.js']) {
    assert.equal(fs.existsSync(path.join(f.scan, name)), false, name);
  }
}));

test('candidate tools and package hooks cannot reach scanner execution', () => fixture((f) => {
  f.write(f.candidate, 'package.json', JSON.stringify({ scripts: { preinstall: 'touch EXECUTED' } }));
  f.write(f.candidate, '.venv/bin/ruff', 'touch EXECUTED');
  f.write(f.candidate, 'node_modules/.bin/ruff', 'touch EXECUTED');
  prepare(f.candidate, f.scan, f.trusted);
  for (const name of ['EXECUTED', '.venv', 'node_modules']) assert.equal(fs.existsSync(path.join(f.scan, name)), false);
}));

for (const kind of ['source', 'configuration']) {
  test(`candidate ${kind} symlinks cannot redirect scanning`, () => fixture((f) => {
    fs.symlinkSync(f.trusted, path.join(f.candidate, kind === 'source' ? 'src' : '.aislop'));
    assert.throws(() => prepare(f.candidate, f.scan, f.trusted), /symlink rejected/);
  }));
}

for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
  test(`candidate ${section} cannot enable executable Knip plugins`, () => fixture((f) => {
    f.write(f.candidate, 'package.json', JSON.stringify({ [section]: { knip: '1' } }));
    assert.throws(() => prepare(f.candidate, f.scan, f.trusted), /Knip execution/);
  }));
}

test('candidate inline Aislop suppression fails before scanning', () => fixture((f) => {
  f.write(f.candidate, 'source.py', '# ' + 'aislop' + '-ignore-file\neval(input())');
  assert.throws(() => prepare(f.candidate, f.scan, f.trusted), /suppression rejected/);
}));

function manifests(f) {
  for (const directory of ['.', 'ui', '.github/scripts']) {
    f.write(f.candidate, path.join(directory, 'package.json'), JSON.stringify({ name: 'fixture', scripts: { install: 'touch EXECUTED' } }));
    f.write(f.candidate, path.join(directory, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {} }));
    f.write(f.candidate, path.join(directory, '.npmrc'), 'registry=https://attacker.invalid');
    f.write(f.candidate, path.join(directory, 'npm-shrinkwrap.json'), '{}');
  }
  f.write(f.candidate, 'requirements.txt', 'example==1.0 \\\n    --hash=sha256:' + 'a'.repeat(64) + '\n');
}

test('audit tree contains only candidate manifests, locks and validated pinned requirements', () => fixture((f) => {
  manifests(f);
  prepareAudits(f.candidate, f.audits);
  for (const directory of ['.', 'ui', '.github/scripts']) {
    assert.ok(fs.existsSync(path.join(f.audits, directory, 'package-lock.json')));
    assert.equal(fs.existsSync(path.join(f.audits, directory, '.npmrc')), false);
    assert.equal(fs.existsSync(path.join(f.audits, directory, 'npm-shrinkwrap.json')), false);
    assert.equal(fs.existsSync(path.join(f.audits, directory, 'EXECUTED')), false);
  }
  assert.equal(fs.readFileSync(path.join(f.audits, 'requirements.txt'), 'utf8'), fs.readFileSync(path.join(f.candidate, 'requirements.txt'), 'utf8'));
}));

for (const requirements of ['-r attacker.txt', '--index-url https://attacker.invalid', 'thing @ https://attacker.invalid/pkg', '-e .', 'thing==1']) {
  test(`audit rejects executable or unlocked requirement: ${requirements}`, () => fixture((f) => {
    manifests(f);
    f.write(f.candidate, 'requirements.txt', requirements);
    assert.throws(() => prepareAudits(f.candidate, f.audits), /pinned versions/);
  }));
}

test('audit rejects manifest parent symlinks', () => fixture((f) => {
  manifests(f);
  fs.renameSync(path.join(f.candidate, 'ui'), path.join(f.root, 'outside'));
  fs.symlinkSync(path.join(f.root, 'outside'), path.join(f.candidate, 'ui'));
  assert.throws(() => prepareAudits(f.candidate, f.audits), /symlink parents/);
}));


test('security tree retains configuration files as scan targets', () => fixture((f) => {
  f.write(f.candidate, 'pyproject.toml', '[tool.malicious]\nsecret = "scan this"\n');
  f.write(f.candidate, '.github/workflows/unsafe.yml', 'run: eval(input)\n');
  prepare(f.candidate, f.scan, f.trusted, true);
  assert.equal(fs.readFileSync(path.join(f.scan, 'pyproject.toml'), 'utf8'), '[tool.malicious]\nsecret = "scan this"\n');
  assert.ok(fs.existsSync(path.join(f.scan, '.github/workflows/unsafe.yml')));
}));



for (const directive of ['eslint' + '-disable-next-line', 'biome' + '-ignore']) {
  test(`candidate ${directive} cannot suppress raw HTML findings`, () => fixture((f) => {
    f.write(f.candidate, 'view.tsx', '// ' + directive + ' react/no-danger dangerouslySetInnerHTML\n' +
      'export const View = ({value}) => <div dangerouslySetInnerHTML={{__html:value}}/>;\n');
    assert.throws(() => prepare(f.candidate, f.scan, f.trusted), /native scanner suppression/);
  }));
}

test('ordinary quoted directive text remains unchanged', () => fixture((f) => {
  const source = 'const quoted = "' + 'biome' + '-ignore lint: fixture";\n';
  f.write(f.candidate, 'fixture.ts', source);
  prepare(f.candidate, f.scan, f.trusted);
  assert.equal(fs.readFileSync(path.join(f.scan, 'fixture.ts'), 'utf8'), source);
}));

test('binary candidate bytes remain unchanged', () => fixture((f) => {
  const bytes = Buffer.from([0, 255, 254, 128, 10]);
  f.write(f.candidate, 'image.bin', bytes);
  prepare(f.candidate, f.scan, f.trusted);
  assert.deepEqual(fs.readFileSync(path.join(f.scan, 'image.bin')), bytes);
}));


for (const suffix of ['', '-next-line', '-line', '-file']) {
  test(`candidate oxlint exclusion ${suffix || 'block'} fails before scanning`, () => fixture((f) => {
    f.write(f.candidate, 'debug.js', '// ' + 'oxlint' + '-disable' + suffix + ' no-debugger\ndebugger;\n');
    assert.throws(() => prepare(f.candidate, f.scan, f.trusted), /native scanner suppression/);
  }));
}

test('quoted Aislop directive cannot suppress adjacent raw HTML', () => fixture((f) => {
  f.write(f.candidate, 'view.tsx', 'const marker = "' + 'aislop' + '-ignore dangerouslySetInnerHTML";\n' +
    'export const View = ({value}) => <div dangerouslySetInnerHTML={{__html:value}}/>;\n');
  assert.throws(() => prepare(f.candidate, f.scan, f.trusted), /native scanner suppression/);
}));
