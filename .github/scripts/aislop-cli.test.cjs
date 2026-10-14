const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { resolve } = require('node:path');
const { performance } = require('node:perf_hooks');

test('pinned ci --sarif preserves the score threshold with warning-only findings', { timeout: 90_000 }, (t) => {
  const root = resolve(__dirname, '../..');
  const expectedVersion = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')).devDependencies.aislop;
  const installed = resolve(root, 'node_modules/aislop');
  const packageJson = JSON.parse(readFileSync(resolve(installed, 'package.json'), 'utf8'));
  assert.equal(packageJson.version, expectedVersion);
  const cli = resolve(installed, packageJson.bin.aislop);
  const directory = mkdtempSync(resolve(tmpdir(), 'aislop-score-regression-'));
  const started = performance.now();
  try {
    mkdirSync(resolve(directory, 'src'));
    mkdirSync(resolve(directory, '.aislop'));
    writeFileSync(resolve(directory, 'package.json'), JSON.stringify({
      name: 'aislop-score-regression', version: '1.0.0', type: 'module',
    }));
    writeFileSync(resolve(directory, 'src/example.js'),
      'export const api_key = "abcdefghijklmnopqrstuvwxyz0123456789";\n');

    for (const [threshold, expectedStatus] of [[100, 1], [0, 0]]) {
      writeFileSync(resolve(directory, '.aislop/config.yml'), [
        'engines:', '  format: false', '  lint: false', '  code-quality: false', '  ai-slop: false',
        '  security: true', 'security:', '  audit: false',
        'ci:', `  failBelow: ${threshold}`, 'telemetry:', '  enabled: false',
        'rules:', '  security/hardcoded-secret: warning', '',
      ].join('\n'));
      const result = spawnSync(process.execPath, [cli, 'ci', '--sarif'], {
        cwd: directory,
        env: { ...process.env, CI: '1', AISLOP_NO_TELEMETRY: '1', DO_NOT_TRACK: '1', NO_COLOR: '1' },
        encoding: 'utf8',
        timeout: 30_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, expectedStatus, result.stderr);
      const report = JSON.parse(result.stdout);
      assert.equal(report.version, '2.1.0');
      assert.equal(report.runs.length, 1);
      assert.equal(report.runs[0].tool.driver.version, expectedVersion);
      const findings = report.runs[0].results;
      assert.ok(findings.some((finding) => finding.ruleId === 'security/hardcoded-secret' && finding.level === 'warning'));
      assert.ok(findings.every((finding) => finding.level !== 'error'));
    }
    t.diagnostic(`Two small fixture scans took ${Math.round(performance.now() - started)} ms; no dependency install.`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
