# Dependabot auto-merge

- All verified Dependabot updates can auto-merge, including major updates.
- Required repository checks must pass. Merges use squash.
- Unsigned or non-Dependabot commits require manual review.
- PR events and the 30-minute refresh use the same implementation.
- Dependabot handles its own branch updates with `rebase-strategy: auto`.
  Each ecosystem runs daily on a staggered cron schedule, so stale PRs are
  rebased by Dependabot and trigger normal PR checks. The general PR
  branch updater never writes to Dependabot branches or posts bot commands.
- `GITHUB_TOKEN` handles auto-merge and main-workflow dispatch. No App or PAT.
- The refresh starts missing main validation for the current Dependabot merge.
  It dispatches the inputless `main` workflow on the default branch. Existing runs
  are reused; failed runs remain visible. This dispatch cannot publish a release.
- Dependency updates include their generated hashes in the same PR: pip hashes in
  `requirements.txt` and `dev-requirements.txt`, and npm integrity values in each
  `package-lock.json`. Required checks install those exact locks and verify the
  Python locks are current before merging. Dependabot rebases rerun these checks.
  Release-policy approval hashes still require review; frozen release manifests
  and published artifact checksums are never refreshed by Dependabot.

To re-evaluate open PRs, run **Actions → dependabot auto-merge refresh → Run
workflow** on the default branch.

For an existing stuck PR, use Dependabot's `@dependabot rebase` command.
Dependabot may stop updating PRs with extra commits or after 30 days;
review any manual changes before requesting recreation.
