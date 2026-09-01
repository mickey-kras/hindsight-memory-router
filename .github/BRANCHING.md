# Repository workflow

- `main` is the only permanent branch.
- Protect `main` from deletion and force pushes.
- Same-repository work branches must match `^(feat|fix|refactor|docs|ci|security)/[a-z0-9]+(-[a-z0-9]+)*$`.
- Allowed forms: `feat/<short-description>`, `fix/<short-description>`, `refactor/<short-description>`, `docs/<short-description>`, `ci/<short-description>`, or `security/<short-description>`, with `<short-description>` required to be lowercase kebab-case.
- Native ruleset `Enforce work branch names` targets all branches, excludes `main`, `dependabot/*`, and the six allowed work prefixes, and enables `Restrict creations`. This rejects unsupported prefixes before the branch is created.
- The `branch-policy` PR check enforces the full regex because native `fnmatch` prefix exclusions do not validate lowercase kebab-case suffixes.
- `dependabot/*` is the only automated exception; the native ruleset bypass is limited to Dependabot and the PR check accepts that prefix only for PRs authored by `dependabot[bot]`.
- External fork branch names are not restricted.
- Merge through a pull request after required checks; resolve review conversations and use squash merge. GitHub automatically deletes merged same-repository head branches. Required approving reviews are `0` while the repository has a single maintainer.
- Releases use SemVer tags such as `v0.10.0` or `v1.0.0-rc.1` on commits reachable from `main`.
- Native ruleset `Enforce release tag names` targets all tags except `v*` and enables `Restrict creations`, so non-release tag names cannot be created.
- Native ruleset `Protect release tags` targets `v*` and enables `Restrict updates`, `Restrict deletions`, and `Block force pushes`, so release-looking tags are immutable after creation.
- GitHub tag rulesets use `fnmatch`, so they cannot express exact SemVer. `branch-policy` and the publish workflow reject malformed `v*` tags and tags not reachable from `main` for CI/publishing, but cannot remove them after creation because native tag immutability applies immediately.
- No release branches.
- Architecture-affecting PRs update `docs/architecture/workspace.dsl` and refresh generated diagrams with `make architecture` in the same PR.
