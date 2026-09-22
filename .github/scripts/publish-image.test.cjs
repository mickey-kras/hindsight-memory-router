const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, writeFileSync, readFileSync, rmSync, chmodSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

function fixture(fn) {
  const directory = mkdtempSync(join(tmpdir(), 'publish-image-test-'));
  const statePath = join(directory, 'state.json');
  const put = (state) => writeFileSync(statePath, JSON.stringify(state));
  const get = () => JSON.parse(readFileSync(statePath, 'utf8'));
  const docker = join(directory, 'docker');
  writeFileSync(docker, `#!${process.execPath}
const fs = require('node:fs');
const [cmd, sub, ...rest] = process.argv.slice(2);
const state = JSON.parse(fs.readFileSync(process.env.MOCK_STATE, 'utf8'));
const config = 'sha256:' + 'c'.repeat(64);
if (cmd === 'image') {
  process.stdout.write(rest.at(-1) === '{{.Id}}' ? config : (process.env.MOCK_REVISION || process.env.SOURCE_SHA || process.env.GITHUB_SHA));
} else if (cmd === 'manifest') {
  if (state.denied) { process.stderr.write('unauthorized'); process.exit(1); }
  if (state.different || state.existing.includes(rest[0])) {
    if (state.index) {
      process.stdout.write(JSON.stringify({mediaType: 'application/vnd.oci.image.index.v1+json', manifests: []}));
    } else {
      process.stdout.write(JSON.stringify({config: {digest: state.different ? 'wrong' : config}}));
    }
  } else { process.stderr.write('no such manifest'); process.exit(1); }
} else if (cmd === 'push') {
  state.pushes.push(sub);
  fs.writeFileSync(process.env.MOCK_STATE, JSON.stringify(state));
  if (state.fail === sub) { process.stderr.write(state.failMessage || 'push failed'); process.exit(1); }
  if (state.transient && state.transient.tag === sub && state.transient.times > 0) {
    state.transient.times -= 1;
    fs.writeFileSync(process.env.MOCK_STATE, JSON.stringify(state));
    process.stderr.write(state.transient.message);
    process.exit(1);
  }
  state.existing.push(sub);
  fs.writeFileSync(process.env.MOCK_STATE, JSON.stringify(state));
} else if (cmd === 'buildx') {
  process.stdout.write(JSON.stringify('sha256:' + 'd'.repeat(64)));
} else if (cmd !== 'tag') { throw new Error('unexpected docker command'); }
`);
  chmodSync(docker, 0o755);
  const env = { ...process.env, PATH: `${directory}:${process.env.PATH}`, MOCK_STATE: statePath,
    VERSION: '0.1.0', SOURCE_IMAGE: 'tested:image', IMAGE_GHCR: 'ghcr.io/example/router',
    IMAGE_DOCKERHUB: 'docker.io/example/router', GITHUB_SHA: 'a'.repeat(40),
    RUNNER_TEMP: directory, GITHUB_OUTPUT: join(directory, 'outputs') };
  const run = () => spawnSync('bash', [join(__dirname, 'publish-image.sh')], { env, encoding: 'utf8' });
  put({ existing: [], pushes: [] });
  try { fn({ run, put, get, env }); } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('scan-to-push promotion refuses different existing images and registry errors before any push', () => fixture(({ run, put, get }) => {
  for (const flag of ['different', 'denied']) {
    put({ existing: [], pushes: [], [flag]: true });
    assert.notEqual(run().status, 0);
    assert.deepEqual(get().pushes, []);
  }
}));

test('scan-to-push promotion refuses existing multi-arch index manifests before any push', () => fixture(({ run, put, get, env }) => {
  put({ existing: [`${env.IMAGE_GHCR}:${env.VERSION}`], pushes: [], index: true });
  assert.notEqual(run().status, 0);
  assert.deepEqual(get().pushes, []);
}));

test('transient registry errors are retried with backoff until the push succeeds', () => fixture(({ run, put, get, env }) => {
  const flakyTag = `${env.IMAGE_GHCR}:${env.VERSION}`;
  put({ existing: [], pushes: [], transient: { tag: flakyTag, times: 2, message: 'unknown blob' } });
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(get().pushes.filter(tag => tag === flakyTag).length, 3);
  assert.match(result.stderr, /retrying/);
  assert.match(readFileSync(env.GITHUB_OUTPUT, 'utf8'), /published=true/);
}));

test('persistent transient errors exhaust three attempts and fail the push', () => fixture(({ run, put, get, env }) => {
  const flakyTag = `${env.IMAGE_GHCR}:${env.VERSION}`;
  put({ existing: [], pushes: [], transient: { tag: flakyTag, times: 99, message: 'i/o timeout' } });
  assert.notEqual(run().status, 0);
  assert.equal(get().pushes.filter(tag => tag === flakyTag).length, 3);
  assert.deepEqual(get().existing, []);
}));

test('permanent and unrecognized push errors fail without retries', () => fixture(({ run, put, get, env }) => {
  const tag = `${env.IMAGE_GHCR}:${env.VERSION}`;
  for (const failMessage of ['denied: requested access to the resource is denied',
    'unauthorized: authentication required', 'blob upload invalid']) {
    put({ existing: [], pushes: [], fail: tag, failMessage });
    assert.notEqual(run().status, 0);
    assert.deepEqual(get().pushes, [tag]);
  }
}));

test('partial registry publication resumes only missing tags without overwriting existing ones', () => fixture(({ run, put, get, env }) => {
  const failedTag = `${env.IMAGE_DOCKERHUB}:${env.VERSION}`;
  put({ existing: [], pushes: [], fail: failedTag });
  assert.notEqual(run().status, 0);
  const partial = get();
  assert.equal(partial.existing.length, 2);
  delete partial.fail; partial.pushes = []; put(partial);
  const resumed = run();
  assert.equal(resumed.status, 0, resumed.stderr);
  assert.deepEqual(get().pushes, [failedTag, `${env.IMAGE_DOCKERHUB}:${env.GITHUB_SHA}`]);
  assert.match(readFileSync(env.GITHUB_OUTPUT, 'utf8'), /published=true/);
  const completed = get(); completed.pushes = []; put(completed);
  assert.equal(run().status, 0);
  assert.deepEqual(get().pushes, []);
}));

test('main dispatch publishes candidate tags and rejects an image built from the workflow SHA', () => fixture(({ run, get, put, env }) => {
  env.SOURCE_SHA = 'b'.repeat(40);
  assert.equal(run().status, 0);
  assert.deepEqual(get().pushes, [`${env.IMAGE_GHCR}:${env.VERSION}`, `${env.IMAGE_GHCR}:${env.SOURCE_SHA}`,
    `${env.IMAGE_DOCKERHUB}:${env.VERSION}`, `${env.IMAGE_DOCKERHUB}:${env.SOURCE_SHA}`]);
  put({ existing: [], pushes: [] });
  env.MOCK_REVISION = env.GITHUB_SHA;
  assert.notEqual(run().status, 0);
  assert.deepEqual(get().pushes, []);
}));
