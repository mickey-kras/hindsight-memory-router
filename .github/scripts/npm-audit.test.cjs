const { test } = require('node:test');
const assert = require('node:assert/strict');
const { findings } = require('./npm-audit.cjs');

test('returns every other moderate or higher vulnerability', () => {
  const hono = { severity: 'high', fixAvailable: true, via: [] };
  assert.deepEqual(findings({ vulnerabilities: { hono } }), [['hono', hono]]);
});

test('returns inherited moderate vulnerabilities without exceptions', () => {
  const admZip = { severity: 'moderate', isDirect: false, effects: ['aislop'] };
  assert.deepEqual(findings({ vulnerabilities: { 'adm-zip': admZip } }), [['adm-zip', admZip]]);
});

test('drops the package named by an ignored advisory and its dependents', () => {
  const ghsa = 'GHSA-fc5q-39xc-vjpf';
  const picomatch = {
    severity: 'high',
    via: [{ source: ghsa, name: 'picomatch', dependency: 'picomatch', title: 'ReDoS' }],
    effects: ['aislop', 'fdir', 'knip', 'tinyglobby'],
  };
  const fdir = { severity: 'high', via: ['picomatch'] };
  const tinyglobby = { severity: 'high', via: ['fdir', 'picomatch'] };
  const knip = { severity: 'high', via: ['tinyglobby'] };
  const other = { severity: 'high', via: [{ source: 'GHSA-other-0000-0000' }] };
  assert.deepEqual(
    findings({ vulnerabilities: { picomatch, fdir, tinyglobby, knip, other } }, new Set([ghsa])),
    [['other', other]],
  );
});

test('keeps dependents that still have a non-suppressed path', () => {
  const ghsa = 'GHSA-fc5q-39xc-vjpf';
  const picomatch = { severity: 'high', via: [{ source: ghsa }] };
  const dual = { severity: 'high', via: ['picomatch', { source: 'GHSA-real-0000-0000' }] };
  assert.deepEqual(
    findings({ vulnerabilities: { picomatch, dual } }, new Set([ghsa])),
    [['dual', dual]],
  );
});

test('ignores nothing when the ignore set is empty', () => {
  const picomatch = { severity: 'high', via: [{ source: 'GHSA-fc5q-39xc-vjpf' }] };
  assert.deepEqual(findings({ vulnerabilities: { picomatch } }), [['picomatch', picomatch]]);
});
