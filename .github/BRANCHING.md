# Repository workflow

- `main` is the only permanent branch.
- Same-repository work uses `feat/`, `fix/`, `refactor/`, `docs/`, `ci/`, or `security/` followed by a lowercase kebab-case short description.
- External fork branch names are not restricted.
- Merge through a pull request after required checks and review; use squash merge and delete the branch.
- Releases use immutable SemVer tags such as `v0.10.0` or `v1.0.0-rc.1` on commits reachable from `main`.
- No release branches.
