# Dependabot auto-merge

- All verified Dependabot updates can auto-merge, including major updates.
- Required repository checks must pass. Merges use squash.
- Unsigned or non-Dependabot commits require manual review.
- PR events and the 30-minute refresh use the same implementation.
- Every main update requests recreation of stale, verified Dependabot PRs.
  Requests are deduplicated per head; untrusted commits require manual review.
  Regular PR branches are updated when they have no merge conflicts.
- `.github/actions/refresh-prs` owns branch refresh for both repositories.
  Integrations pins its commit and supplies its generated-artifact verifier.
  Dependabot's daily rebasing remains enabled as a fallback.
- `GITHUB_TOKEN` handles auto-merge and main-workflow dispatch. No App or PAT.
- The refresh starts missing main validation for the current Dependabot merge.
  Existing runs are reused; failed runs remain visible.

To re-evaluate open PRs, run **Actions → dependabot auto-merge refresh → Run
workflow** on the default branch.

To retry branch refresh, run **Actions → pr branch updater → Run workflow**.
