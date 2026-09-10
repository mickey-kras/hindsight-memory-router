const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function verifyDependabot(github, repo, pull, commits) {
  if (!commits.length || !commits.every(commit =>
    commit.author?.login === 'dependabot[bot]' && commit.author.id === 49699333 &&
    commit.commit.verification?.verified)) throw new Error('Untrusted commits require manual review');
}

async function recreatePull({ github, owner, repo, pull, verifyCommits }) {
  if (!pull.head.ref.startsWith('dependabot/')) return 'ineligible';
  const params = { owner, repo, pull_number: pull.number };
  const commits = await github.paginate(github.rest.pulls.listCommits, { ...params, per_page: 100 });
  await verifyCommits(github, { owner, repo }, pull, commits);
  const body = `@dependabot recreate\n\n<!-- dependency-refresh:${pull.head.sha} -->`;
  const issue = { owner, repo, issue_number: pull.number };
  const comments = await github.paginate(github.rest.issues.listComments, { ...issue, per_page: 100 });
  if (comments.some(comment => comment.body === body && comment.user.id === 41898282)) {
    return 'recreation already requested';
  }
  const { data: current } = await github.rest.pulls.get(params);
  if (current.state !== 'open' || current.head.sha !== pull.head.sha ||
      current.base.ref !== pull.base.ref || current.head.repo?.full_name !== `${owner}/${repo}`) {
    return 'changed during evaluation';
  }
  await github.rest.issues.createComment({ ...issue, body });
  return 'recreation requested';
}

async function updatePull({ github, owner, repo, number, sleep, verifyCommits }) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const { data: pull } = await github.rest.pulls.get({ owner, repo, pull_number: number });
    if (pull.state !== 'open' || pull.base.ref !== 'main' ||
        pull.head.repo?.full_name !== `${owner}/${repo}`) return 'ineligible';
    // PR base metadata can lag behind the branch tip after a merge.
    const { data: main } = await github.rest.git.getRef({ owner, repo, ref: 'heads/main' });
    const { data: comparison } = await github.rest.repos.compareCommitsWithBasehead({
      owner, repo, basehead: `${pull.head.sha}...${main.object.sha}`,
    });
    // With the PR head as the comparison base, ahead_by counts missing main commits.
    if (comparison.ahead_by === 0) return 'current';
    if (!Number.isInteger(comparison.ahead_by) || comparison.ahead_by < 0) {
      throw new Error('invalid commit comparison');
    }
    if (pull.user?.login === 'dependabot[bot]' && pull.user.id === 49699333) {
      return recreatePull({ github, owner, repo, pull, verifyCommits });
    }
    if (pull.mergeable === false) return 'conflicting';
    if (pull.mergeable === true) {
      await github.request('PUT /repos/{owner}/{repo}/pulls/{pull_number}/update-branch', {
        owner, repo, pull_number: number, expected_head_sha: pull.head.sha,
      });
      return 'update requested';
    }
    if (attempt < 3) await sleep(5000);
  }
  throw new Error('mergeability remained unknown after 4 attempts');
}

async function run({ github, context, core, sleep = pause, verifyCommits = verifyDependabot }) {
  const { owner, repo } = context.repo;
  const pulls = await github.paginate(github.rest.pulls.list, {
    owner, repo, state: 'open', base: 'main', per_page: 100,
  });
  const results = [];
  let unresolved = 0;
  for (const pull of pulls) {
    let status;
    try {
      status = pull.head.repo?.full_name === `${owner}/${repo}`
        ? await updatePull({ github, owner, repo, number: pull.number, sleep, verifyCommits })
        : 'ineligible';
    } catch (error) {
      status = `unresolved: ${error.message}`;
      unresolved++;
    }
    core.info(`#${pull.number}: ${status}`);
    results.push([String(pull.number), status]);
  }
  await core.summary.addHeading('PR branch updates').addTable([
    [{ data: 'PR', header: true }, { data: 'Result', header: true }], ...results,
  ]).write();
  if (unresolved) core.setFailed(`${unresolved} PR branch update(s) unresolved`);
}

module.exports = { run };
