# Dependabot auto-merge

[Documentation](README.md) | [Repository](../README.md)

- Only examined and accepted Dependabot updates can auto-merge.
  Signed commit metadata must classify every updated dependency as a semantic-version patch or minor update.
  Major updates and missing, invalid or unclassified metadata must have a human review.
- The required repository checks must pass.
  Merges use squash.
- Unsigned or non-Dependabot commits must have a manual review.
- PR events and the 30-minute refresh use the same implementation.
  Automation re-evaluates auto-merge decisions enabled by `github-actions[bot]`.
  It withdraws them when the update is ineligible.
  It preserves decisions enabled by human users.
  It also preserves a disable observed during evaluation.
- Dependabot handles its own branch updates with `rebase-strategy: auto`.
  Each ecosystem runs daily on a staggered cron schedule.
  Dependabot rebases stale PRs and triggers normal PR checks.
  The general PR branch updater never writes to Dependabot branches or posts bot commands.
- `GITHUB_TOKEN` handles auto-merge and main-workflow dispatch.
  The workflow uses no App or PAT.
- The refresh starts missing main validation for the current Dependabot merge.
  It dispatches the `main` workflow without inputs on the default branch.
  The workflow uses existing runs again.
  Failed runs stay visible.
  This dispatch cannot publish a release.
- Dependency updates include their generated hashes in the same PR.
  These include pip hashes in `requirements.txt` and `dev-requirements.txt`, and npm integrity values in each `package-lock.json`.
  The required checks install those exact locks.
  Before the merge, they make sure that Python locks are current.
  Dependabot rebases rerun these checks.
  Release-policy approval hashes must also have a review.

  Dependabot never refreshes frozen release manifests or published artifact checksums.

To re-evaluate open PRs, run **Actions > dependabot auto-merge refresh > Run
workflow** on the default branch.

For an existing stuck PR, use Dependabot's `@dependabot rebase` command.
Dependabot can stop its updates of PRs with extra commits or after 30 days.
Review all manual changes before you ask Dependabot to recreate the PR.

