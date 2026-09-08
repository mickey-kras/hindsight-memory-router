const { test } = require('node:test');
const assert = require('node:assert/strict');
const { findings, waived } = require('./npm-audit.cjs');

const advisory = { severity: 'moderate', fixAvailable: false, isDirect: false,
  effects: ['aislop'], via: [{ url: 'https://github.com/advisories/GHSA-vwc7-r8mq-g2x9' }] };
const parent = { severity: 'moderate', fixAvailable: false, isDirect: true,
  effects: [], via: ['adm-zip'] };

test('accepts only the no-fix adm-zip advisory inherited through Aislop', () => {
  assert.equal(waived('adm-zip', advisory), true);
  assert.equal(waived('aislop', parent), true);
  assert.deepEqual(findings({ vulnerabilities: { 'adm-zip': advisory, aislop: parent } }), []);
});

test('fails closed when the package path, advisory, or fix availability changes', () => {
  for (const changed of [
    { ...advisory, effects: ['other'] },
    { ...advisory, via: [{ url: 'https://github.com/advisories/other' }] },
    { ...advisory, fixAvailable: true },
  ]) assert.equal(waived('adm-zip', changed), false);
});

test('returns every other moderate or higher vulnerability', () => {
  const hono = { severity: 'high', fixAvailable: true, via: [] };
  assert.deepEqual(findings({ vulnerabilities: { hono } }), [['hono', hono]]);
});
