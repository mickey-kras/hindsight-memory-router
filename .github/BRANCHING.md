# Repository workflow

[Documentation](../docs/README.md) | [Repository](../README.md)

- `main` is the only permanent branch.
- Protect `main` from deletion and force pushes.
- Same-repository work branches must match `^(feat|fix|refactor|docs|ci|security)/[a-z0-9]+(-[a-z0-9]+)*$`.
- Allowed forms: `feat/<short-description>`, `fix/<short-description>`, `refactor/<short-description>`, `docs/<short-description>`, `ci/<short-description>`, or `security/<short-description>`, where `<short-description>` must be lowercase kebab-case.
- Native ruleset `Enforce work branch names` targets all branches, excludes `main`, `dependabot/*`, and the six allowed work prefixes, and enables `Restrict creations`. This rejects unsupported prefixes before GitHub creates the branch.
- The `branch-policy` PR check enforces the full regex because native `fnmatch` prefix exclusions do not validate lowercase kebab-case suffixes.
- `dependabot/*` is the only automated exception.
  Only Dependabot has the native ruleset bypass.
  The PR check accepts that prefix only for PRs authored by `dependabot[bot]`.
- The rulesets do not restrict the names of branches in external forks.
- Resolve review conversations.
  Merge through a pull request after required checks pass.
  Use squash merge. GitHub automatically deletes merged same-repository head branches. Required approving reviews are `0` while the repository has a single maintainer.
- Base pushes automatically refresh eligible same-repository PRs only while auto-merge is on. Dependabot uses its scheduled native rebasing.
- To refresh a manual PR, run `pr branch updater` on its base branch (`main` or `release/X.Y.Z`).
  Supply the PR's `pull_number`. This refreshes only that PR and reports conflicts or update failures. If you enable auto-merge after the last base push, do an explicit refresh or push the base again.
- Strict required checks must have the current base before the merge. After a refresh, examine the checks and review comments of the new head.
  If the base advances, refresh the branch again.
  Examine the new head again.
- Releases use plain SemVer tags such as `v0.10.0` on prepared release commits descending from `main`.
- Native ruleset `Enforce release tag names` targets all tags except `v*` and enables `Restrict creations`, so nobody can create a tag with a non-release name.
- The native ruleset `Protect release tags` applies to `v*` tags. It enables `Restrict updates`, `Restrict deletions`, and `Block force pushes`, so nobody can change a release tag after its creation.
- GitHub tag rulesets use `fnmatch`, so they cannot express exact SemVer. For CI/publishing, `branch-policy` and the publish workflow reject malformed `v*` tags and tags not reachable from `main`.
  They cannot remove these tags after creation because native tag immutability applies immediately.
- Automation creates protected `release/X.Y.Z` branches. Failed or canceled candidates stay for a retry. Successful publication and follow-up delete the branch.
- For PRs that affect architecture, update `docs/architecture/workspace.dsl`.
  Refresh generated diagrams with `make architecture` in the same PR.

## Documentation language

Use ASD-STE100 Issue 9 for all new or changed documentation.
Use exact technical terms, commands, configuration names, and endpoint paths.
Do not change commands or legal quotations only to satisfy prose rules.
Check the applicable writing rules and dictionary entries.
Sentence-length checks alone do not prove full compliance.
