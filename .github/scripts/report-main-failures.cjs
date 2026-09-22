const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { stripVTControlCharacters } = require('node:util');

const REPORTABLE = new Set(['failure', 'timed_out', 'action_required', 'startup_failure']);
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function clean(text) {
  return stripVTControlCharacters(text).replace(/\r/g, '')
    .replace(/[a-z][a-z0-9+.-]*:\/\/[^\s<>]+/g, value => {
      try {
        const url = new URL(value);
        url.username = ''; url.password = ''; url.search = ''; url.hash = '';
        return url.toString();
      } catch { return '[url]'; }
    })
    .replace(/\b(Bearer|Basic)\s+\S+/gi, '$1 [redacted]')
    .replace(/((?:token|password|secret|api[_-]?key)\s*[=:]\s*)\S+/gi, '$1[redacted]')
    .replace(/@/g, '＠').replace(/<!--/g, '&lt;!--').replace(/```/g, "'''");
}

function normalize(text) {
  return clean(text).replace(/^\d{4}-\d\d-\d\dT[\d:.]+Z\s*/, '')
    .replace(/\/home\/runner\/work\/_temp\/[^\s]+/g, '<temporary-path>')
    .trim();
}

function stepLines(log, step) {
  // GitHub step boundaries have second precision; log timestamps include fractions.
  const start = Date.parse(step.started_at), end = Date.parse(step.completed_at);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return [];
  return log.split('\n').filter(line => {
    const timestamp = Date.parse(line.split(' ')[0]);
    return timestamp >= start && timestamp < end + 1000;
  }).map(normalize).filter(Boolean);
}

function diagnostics(lines) {
  // Only explicit diagnostics participate in grouping. Exit codes alone are ambiguous.
  const tests = lines.filter(line => /^FAILED\s+\S+::\S+\s+-\s+\S/.test(line));
  if (tests.length) return [...new Set(tests)];
  const smoke = lines.filter(line => line.startsWith('HMR_FAILURE_JSON=')).flatMap(line => {
    try {
      const failure = JSON.parse(line.slice('HMR_FAILURE_JSON='.length));
      if (!failure.check || !failure.storage || !failure.mode) return [];
      return [JSON.stringify({ mode: failure.mode, storage: failure.storage,
        check: failure.check, message: failure.message || null })];
    } catch { return []; }
  });
  if (smoke.length) return [...new Set(smoke)];
  const updates = lines.filter(line => /^#\d+: unresolved: \S/.test(line));
  if (updates.length) return [...new Set(updates)];
  const errors = lines.filter(line =>
    /^(?:[\w.]+(?:Error|Exception):\s+\S|##\[error\]\S)/.test(line) &&
    !/Process completed with exit code|The operation was canceled|Quality Gate has FAILED/.test(line));
  // Preserve all diagnostic lines together when their relationship is unknown.
  return errors.length ? [[...new Set(errors)].join('\n')] : [];
}

function reportsForJob(run, job, log, fallback = '') {
  if (run.conclusion === 'cancelled' || !REPORTABLE.has(job.conclusion)) return [];
  const steps = (job.steps || []).filter(step => REPORTABLE.has(step.conclusion));
  if (!steps.length) steps.push({ name: job.conclusion, number: 0 });
  return steps.flatMap(step => {
    const lines = stepLines(log, step);
    const details = diagnostics(lines);
    return (details.length ? details : [null]).map(detail => {
      const incompleteSmoke = detail?.startsWith('{"mode":') && !JSON.parse(detail).message;
      const identified = detail && !incompleteSmoke;
      const identity = [job.name, step.name, detail];
      if (!identified) identity.push(run.id, job.id || run.run_attempt, step.number);
      const key = `v2-${hash(identity)}`;
      const occurrence = `${run.id}-${job.id || run.run_attempt}-${step.number}-${key}`;
      const symptoms = lines.filter(line => /HMR_FAILURE_JSON=|current check:|(?:failed|error|exited)(?:[ :.(]|$)/i.test(line));
      const excerpt = (symptoms.length ? symptoms.slice(-50) : lines.slice(-35)).join('\n');
      const diagnostic = identified ? detail : [detail, excerpt].filter(Boolean).join('\n');
      const evidence = clean((diagnostic || fallback || 'Job logs unavailable.').slice(0,10000));
      return { key, occurrence,
        title: clean(`[ci] ${job.name}: ${detail ? detail.split('\n')[0] : `${step.name} — diagnostics incomplete`}`).slice(0,240),
        body: `Validation failed on ${clean(run.head_branch || 'main')}.\n\n- Job / step: ${clean(job.name)} / ${clean(step.name)}\n` +
          `- Commit: ${run.head_sha}\n- Report attempt: ${run.run_attempt}\n- Run: ${run.html_url}\n` +
          `- Job: ${job.html_url}\n- Conclusion: ${job.conclusion}\n\n` +
          (identified ? '' : 'No reliable error signature was available; this issue is scoped to this occurrence.\n\n') +
          `\`\`\`text\n${evidence}\n\`\`\`\n` };
    });
  });
}

function logFallback(api, job, failure) {
  const lines = (job.steps || []).filter(step => REPORTABLE.has(step.conclusion))
    .map(step => `Step "${step.name}" concluded ${step.conclusion}.`);
  try {
    const path = new URL(job.check_run_url).pathname;
    const annotations = JSON.parse(api(`${path}/annotations?per_page=100`));
    lines.push(...annotations.filter(annotation => annotation.annotation_level === 'failure')
      .map(annotation => annotation.message).slice(0, 10));
  } catch { /* Check annotations are best-effort. */ }
  if (failure) lines.push(`Job log download failed: ${String(failure.message).trim().split('\n').at(-1)}`);
  return lines.filter(Boolean).join('\n');
}

function trustedRun(run, repository, defaultBranch) {
  return run.repository?.full_name === repository && run.head_repository?.full_name === repository &&
    ((run.head_branch === defaultBranch && ['push', 'workflow_dispatch'].includes(run.event) &&
      run.path === '.github/workflows/publish.yml') ||
     (/^release\/(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(run.head_branch) &&
      run.event === 'push' && run.path === '.github/workflows/release.yml'));
}

function main(env = process.env, execute = execFileSync,
  sleep = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)) {
  const repository = env.GITHUB_REPOSITORY;
  const id = env.REPORT_RUN_ID || env.GITHUB_RUN_ID;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository || '') || !/^\d+$/.test(id || '')) {
    throw new Error('Repository and numeric run ID are required');
  }
  const api = (path, options = []) => execute('gh', ['api', path, ...options], {
    encoding: 'utf8', timeout: 60000, maxBuffer: 32 * 1024 * 1024,
  });
  const json = path => JSON.parse(api(path));
  const root = `/repos/${repository}`;
  const run = json(`${root}/actions/runs/${id}`);
  const repo = json(root);
  if (!trustedRun(run, repository, repo.default_branch)) throw new Error('Untrusted publish run');
  if (run.conclusion === 'cancelled') return [];
  const pages = JSON.parse(api(`${root}/actions/runs/${id}/jobs?filter=latest&per_page=100`, ['--paginate', '--slurp']));
  const jobs = pages.flatMap(page => page.jobs);
  const issues = JSON.parse(api(`${root}/issues?state=all&per_page=100`, ['--paginate', '--slurp'])).flat();
  const relatedSonar = issues.filter(issue => !issue.pull_request && issue.body?.includes('<!-- sonar-finding:') &&
    issue.body.includes(`- Detected at commit: \`${run.head_sha}\``) && issue.body.includes(`- Workflow: ${run.html_url}`));
  const reports = [];
  for (const job of jobs.filter(job => REPORTABLE.has(job.conclusion))) {
    // Just-finished jobs often 404 on log download while the run is still open.
    let log = '', failure;
    for (let attempt = 0; attempt < 3 && !log; attempt += 1) {
      if (attempt) sleep(10000 * attempt);
      try { log = api(`${root}/actions/jobs/${job.id}/logs`, ['--allow-escape-sequences']); }
      catch (error) { failure = error; }
    }
    const fallback = log ? '' : logFallback(api, job, failure);
    for (const report of reportsForJob(run, job, log, fallback)) {
      // Sonar's stable finding IDs already identify individual causes.
      if (relatedSonar.length && report.body.includes(' / SonarQube quality gate\n')) continue;
      reports.push(report);
    }
  }
  if (!reports.length && !relatedSonar.length && REPORTABLE.has(run.conclusion)) {
    reports.push(...reportsForJob(run, { id: 0, name: 'publish workflow', steps: [],
      conclusion: run.conclusion, html_url: run.html_url }, ''));
  }
  if (!reports.length) return [];
  const completed = [];
  const directory = mkdtempSync(join(tmpdir(), 'main-failures-'));
  try {
    for (const report of reports) {
      if (json(`${root}/actions/runs/${id}`).conclusion === 'cancelled') break;
      const path = join(directory, `${report.key}.md`);
      writeFileSync(path, report.body);
      execute('bash', ['.github/scripts/upsert-main-failure-issue.sh', path], {
        encoding: 'utf8', timeout: 60000,
        env: { ...env, FAILURE_KEY: report.key, FAILURE_TITLE: report.title,
          FAILURE_OCCURRENCE: report.occurrence },
      });
      completed.push(report);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
  return completed;
}

module.exports = { clean, normalize, diagnostics, reportsForJob, logFallback, trustedRun, main };
if (require.main === module) main();
