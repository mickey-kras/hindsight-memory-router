const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const BAD = new Set(['failure', 'timed_out', 'cancelled', 'action_required', 'startup_failure']);
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function clean(text) {
  return text.replace(/\x1b\[[0-9;]*m/g, '').replace(/\r/g, '')
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
  const start = Date.parse(step.started_at), end = Date.parse(step.completed_at);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return [];
  return log.split('\n').filter(line => {
    const timestamp = Date.parse(line.split(' ')[0]);
    return timestamp >= start && timestamp <= end;
  }).map(normalize).filter(Boolean);
}

function diagnostics(lines) {
  // Only explicit diagnostics participate in grouping. Exit codes alone are ambiguous.
  const tests = lines.filter(line => /^FAILED\s+\S+::\S+\s+-\s+\S/.test(line));
  if (tests.length) return [...new Set(tests)];
  const smoke = lines.filter(line => /^HMR_FAILURE_JSON=/.test(line)).flatMap(line => {
    try {
      const failure = JSON.parse(line.slice('HMR_FAILURE_JSON='.length));
      if (!failure.message || !failure.check || !failure.storage || !failure.mode) return [];
      return [JSON.stringify({ mode: failure.mode, storage: failure.storage,
        check: failure.check, message: failure.message })];
    } catch { return []; }
  });
  if (smoke.length) return [...new Set(smoke)];
  const errors = lines.filter(line =>
    /^(?:[\w.]+(?:Error|Exception):\s+\S|##\[error\]\S)/.test(line) &&
    !/Process completed with exit code|The operation was canceled|Quality Gate has FAILED/.test(line));
  // Preserve all diagnostic lines together when their relationship is unknown.
  return errors.length ? [[...new Set(errors)].join('\n')] : [];
}

function reportsForJob(run, job, log) {
  const steps = (job.steps || []).filter(step => BAD.has(step.conclusion));
  if (!steps.length) steps.push({ name: job.conclusion, number: 0 });
  return steps.flatMap(step => {
    const lines = stepLines(log, step);
    const details = diagnostics(lines);
    return (details.length ? details : [null]).map(detail => {
      const identity = [job.name, step.name, detail];
      if (!detail) identity.push(run.id, job.id || run.run_attempt, step.number);
      const key = `v2-${hash(identity)}`;
      const occurrence = `${run.id}-${job.id || run.run_attempt}-${step.number}-${key}`;
      const evidence = clean((detail || lines.slice(-35).join('\n') || 'Job logs unavailable.').slice(0,10000));
      return { key, occurrence,
        title: clean(`[ci] ${job.name}: ${detail ? detail.split('\n')[0] : `${step.name} — diagnostics incomplete`}`).slice(0,240),
        body: `Main publish did not succeed.\n\n- Job / step: ${clean(job.name)} / ${clean(step.name)}\n` +
          `- Commit: ${run.head_sha}\n- Report attempt: ${run.run_attempt}\n- Run: ${run.html_url}\n` +
          `- Job: ${job.html_url}\n- Conclusion: ${job.conclusion}\n\n` +
          (detail ? '' : 'No reliable error signature was available; this issue is scoped to this occurrence.\n\n') +
          `\`\`\`text\n${evidence}\n\`\`\`\n` };
    });
  });
}

function trustedRun(run, repository, defaultBranch) {
  return run.repository?.full_name === repository && run.head_repository?.full_name === repository &&
    run.head_branch === defaultBranch && ['push', 'workflow_dispatch'].includes(run.event) &&
    run.path === '.github/workflows/publish.yml';
}

function main(env = process.env, execute = execFileSync) {
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
  const pages = JSON.parse(api(`${root}/actions/runs/${id}/jobs?filter=latest&per_page=100`, ['--paginate', '--slurp']));
  const jobs = pages.flatMap(page => page.jobs);
  const issues = JSON.parse(api(`${root}/issues?state=all&per_page=100`, ['--paginate', '--slurp'])).flat();
  const relatedSonar = issues.filter(issue => !issue.pull_request && issue.body?.includes('<!-- sonar-finding:') &&
    issue.body.includes(`- Detected at commit: \`${run.head_sha}\``) && issue.body.includes(`- Workflow: ${run.html_url}`));
  const reports = [];
  for (const job of jobs.filter(job => BAD.has(job.conclusion))) {
    let log = '';
    try { log = api(`${root}/actions/jobs/${job.id}/logs`); } catch { /* Report missing diagnostics. */ }
    for (const report of reportsForJob(run, job, log)) {
      // Sonar's stable finding IDs already identify individual causes.
      if (relatedSonar.length && report.body.includes(' / SonarQube quality gate\n')) continue;
      reports.push(report);
    }
  }
  if (!reports.length && !relatedSonar.length && BAD.has(run.conclusion)) {
    reports.push(...reportsForJob(run, { id: 0, name: 'publish workflow', steps: [],
      conclusion: run.conclusion, html_url: run.html_url }, ''));
  }
  const directory = mkdtempSync(join(tmpdir(), 'main-failures-'));
  try {
    for (const report of reports) {
      const path = join(directory, `${report.key}.md`);
      writeFileSync(path, report.body);
      execute('bash', ['.github/scripts/upsert-main-failure-issue.sh', path], {
        encoding: 'utf8', timeout: 60000,
        env: { ...env, FAILURE_KEY: report.key, FAILURE_TITLE: report.title,
          FAILURE_OCCURRENCE: report.occurrence },
      });
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
  return reports;
}

module.exports = { clean, normalize, diagnostics, reportsForJob, trustedRun, main };
if (require.main === module) main();
