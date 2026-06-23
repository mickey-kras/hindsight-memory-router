# Branch protection

Protect `main` before accepting external contributions.

GitHub UI:

```text
Settings -> Branches -> Branch protection rules -> Add rule
Branch name pattern: main
```

Recommended settings:

```text
Require a pull request before merging: enabled
Require approvals: 1
Dismiss stale pull request approvals when new commits are pushed: enabled
Require review from Code Owners: disabled for now
Require status checks to pass before merging: enabled
Require branches to be up to date before merging: enabled
Require conversation resolution before merging: enabled
Require signed commits: optional
Require linear history: optional
Include administrators: enabled if you want to protect yourself from mistakes
Allow force pushes: disabled
Allow deletions: disabled
```

Required status checks after first CI run names are known:

```text
ci / checks
codeql / analyze
```

If GitHub shows different exact check names, select the names produced by the latest green workflow run.

External contributors should never be able to force-push to `main`.
