const { execFileSync } = require('node:child_process');
const YAML = require('yaml');

const BOT = { login: 'dependabot[bot]', id: 49699333 };
const AUTOMATION = { login: 'github-actions[bot]', id: 41898282 };
const ALLOWED_UPDATES = new Set(['version-update:semver-patch', 'version-update:semver-minor']);

function isDependabot(user) {
  return user?.login === BOT.login && user?.id === BOT.id;
}

function verifiedCommits(commits) {
  return commits.length > 0 && commits.every(c => isDependabot(c.author) && c.commit.verification?.verified);
}

function automationOwned(pull) {
  const user = pull.auto_merge?.enabled_by;
  return user?.login === AUTOMATION.login && user?.id === AUTOMATION.id;
}

// Dependabot/fetch-metadata uses this YAML document from the signed commit,
// rather than mutable PR titles, bodies or labels. Missing classifications
// deliberately require human review; do not infer a type from version strings.
function classifiedUpdate(message) {
  if (typeof message !== 'string') return false;
  const fragments = [...message.matchAll(/^---\n([\s\S]*?)^\.\.\.(?:\n|$)/gm)];
  if (fragments.length !== 1) return false;
  try {
    const document = YAML.parseDocument(fragments[0][1], { uniqueKeys: true, stringKeys: true });
    if (document.errors.length || document.warnings.length) return false;
    const metadata = document.toJS({ maxAliasCount: 0 });
    const dependencies = metadata?.['updated-dependencies'];
    return Array.isArray(dependencies) && dependencies.length > 0 && dependencies.every(dependency =>
      dependency && typeof dependency['dependency-name'] === 'string' &&
      dependency['dependency-name'].trim().length > 0 && ALLOWED_UPDATES.has(dependency['update-type']));
  } catch {
    return false;
  }
}

function eligibleCommits(commits, head) {
  return verifiedCommits(commits) && commits.at(-1).sha === head &&
    commits.every(commit => classifiedUpdate(commit.commit.message));
}

async function disableAutoMerge(github, pull) {
  // GitHub has no conditional disable mutation. The caller rechecks the head
  // and enabled_by immediately before this request; a later concurrent manual
  // decision cannot be protected by an API compare-and-swap.
  await github.graphql(`mutation($pullRequestId: ID!) {
    disablePullRequestAutoMerge(input: {pullRequestId: $pullRequestId}) {
      pullRequest { number }
    }
  }`, { pullRequestId: pull.node_id });
}

function trustedPull(pull, repository, branch) {
  return isDependabot(pull.user) && pull.state === 'open' && !pull.draft &&
    pull.head.repo?.full_name === repository && pull.head.ref.startsWith('dependabot/') &&
    pull.base.ref === branch;
}

function mergeCommand(repository, number, options) {
  execFileSync('gh', ['pr', 'merge', String(number), '--repo', repository, ...options], {
    timeout: 30000,
    stdio: 'pipe',
  });
}

async function ensureMainRun({ github, context, core, branch, mainWorkflow }) {
  const repo = context.repo;
  const { data: tip } = await github.rest.repos.getBranch({ ...repo, branch });
  const sha = tip.commit.sha;
  const pulls = await github.paginate(github.rest.repos.listPullRequestsAssociatedWithCommit, {
    ...repo, commit_sha: sha, per_page: 100,
  });
  if (!pulls.some(p => isDependabot(p.user) && p.merged_at && p.merge_commit_sha === sha && p.base.ref === branch)) return;
  const runs = await github.paginate(github.rest.actions.listWorkflowRuns, {
    ...repo, workflow_id: mainWorkflow, branch, head_sha: sha, per_page: 100,
  });
  if (runs.some(r => r.head_sha === sha && ['push', 'workflow_dispatch'].includes(r.event) &&
      !['cancelled', 'skipped'].includes(r.conclusion))) return;
  await github.rest.actions.createWorkflowDispatch({ ...repo, workflow_id: mainWorkflow, ref: branch });
  core.info(`Requested ${mainWorkflow} for the Dependabot merge at ${sha}`);
}

async function run({ github, context, core, mainWorkflow, merge = mergeCommand }) {
  const repository = `${context.repo.owner}/${context.repo.repo}`;
  const { data: repo } = await github.rest.repos.get(context.repo);
  const branch = repo.default_branch;
  // Dispatches from a work branch must never run merge automation.
  if (!['pull_request_target', 'workflow_call'].includes(context.eventName) &&
      context.ref !== `refs/heads/${branch}`) throw new Error('Automation requires the default branch');
  const number = context.payload.pull_request?.number;
  const pulls = number ? [{ number }] : await github.paginate(github.rest.pulls.list, {
    ...context.repo, state: 'open', base: branch, per_page: 100,
  });
  let failed = false;
  for (const candidate of pulls) {
    try {
      const params = { ...context.repo, pull_number: candidate.number };
      const { data: pull } = await github.rest.pulls.get(params);
      if (!isDependabot(pull.user) || pull.state !== 'open') continue;
      // A human's auto-merge decision is outside this automation's ownership.
      if (pull.auto_merge && !automationOwned(pull)) continue;
      let eligible = false;
      try {
        if (trustedPull(pull, repository, branch)) {
          const commits = await github.paginate(github.rest.pulls.listCommits, { ...params, per_page: 100 });
          eligible = eligibleCommits(commits, pull.head.sha);
        }
      } catch (error) {
        failed = true;
        core.warning(`#${pull.number}: metadata lookup failed (${error.name}); requires manual review`);
      }
      const { data: current } = await github.rest.pulls.get(params);
      if (current.state !== 'open' || current.head.sha !== pull.head.sha ||
          (current.auto_merge && !automationOwned(current)) ||
          (pull.auto_merge && !current.auto_merge)) {
        core.info(`#${pull.number}: changed during evaluation; retry on the next event or refresh`);
        continue;
      }
      if (!eligible || !trustedPull(current, repository, branch)) {
        if (automationOwned(current)) await disableAutoMerge(github, current);
        core.info(`#${pull.number}: untrusted, major or unclassified update requires manual review`);
        continue;
      }
      if (current.auto_merge) {
        core.info(`#${pull.number}: classified patch/minor auto-merge is already enabled`);
        continue;
      }
      merge(repository, pull.number, ['--auto', '--squash', '--match-head-commit', pull.head.sha]);
      core.info(`#${pull.number}: verified patch/minor Dependabot update queued for squash merge`);
    } catch (error) {
      failed = true;
      core.warning(`#${candidate.number}: auto-merge evaluation failed (${error.name}); left for retry`);
    }
  }
  await ensureMainRun({ github, context, core, branch, mainWorkflow });
  if (failed) core.setFailed('Some Dependabot PRs could not be evaluated; see warnings');
}

module.exports = { run, trustedPull, verifiedCommits, eligibleCommits, classifiedUpdate, automationOwned, ensureMainRun };
