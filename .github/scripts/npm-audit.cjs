const { spawnSync } = require('node:child_process');

const SEVERITY = { low: 1, moderate: 2, high: 3, critical: 4 };

const IGNORE_GHSAS = new Set(
  (process.env.NPM_AUDIT_IGNORE_GHSAS || '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean),
);

function findings(report, ignoreGhsas = IGNORE_GHSAS) {
  const entries = Object.entries(report.vulnerabilities || {});
  // Drop the packages named by an ignored advisory, then iteratively drop
  // dependents whose only path to a vulnerability runs through dropped packages.
  const suppressed = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, vulnerability] of entries) {
      if (suppressed.has(name)) continue;
      const via = Array.isArray(vulnerability.via) ? vulnerability.via : [];
      const advisoryIgnored = via.some(
        (entry) => entry !== null && typeof entry === 'object' && ignoreGhsas.has(entry.source),
      );
      const pathsOnlyThroughSuppressed =
        via.length > 0 &&
        via.every((entry) => typeof entry === 'string' && suppressed.has(entry));
      if (advisoryIgnored || pathsOnlyThroughSuppressed) {
        suppressed.add(name);
        changed = true;
      }
    }
  }
  return entries.filter(
    ([name, vulnerability]) =>
      !suppressed.has(name) && SEVERITY[vulnerability.severity] >= SEVERITY.moderate,
  );
}

function audit(directory = '.') {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const result = spawnSync('npm', ['audit', '--json', '--audit-level=moderate'], {
      cwd: directory, encoding: 'utf8', timeout: 90000, maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env, npm_config_fetch_timeout: '60000', npm_config_fetch_retries: '1' },
    });
    let report;
    try { report = JSON.parse(result.stdout); } catch { /* Retry registry or npm failures. */ }
    if (report && !report.error) {
      const failures = findings(report);
      if (!failures.length) return;
      console.error(JSON.stringify(Object.fromEntries(failures), null, 2));
      process.exitCode = 1;
      return;
    }
    if (attempt === 3) {
      process.stderr.write(result.stderr || result.stdout || 'npm audit failed without diagnostics\n');
      process.exitCode = 1;
      return;
    }
    console.warn(`npm audit could not reach the registry; retrying (${attempt}/3)`);
  }
}

module.exports = { findings };
if (require.main === module) audit(process.argv[2]);
