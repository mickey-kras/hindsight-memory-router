# Protected release branches

Release branches use the exact namespace `release/v*`, for example `release/v1.2.0`.

GitHub must apply the same repository ruleset requirements to `main` and `release/v*`:

- require changes through pull requests;
- require the same approving-review count;
- dismiss stale approvals when new commits are pushed;
- require approval of the most recent reviewable push when enabled on `main`;
- require all review conversations to be resolved;
- require the same status checks as `main`;
- require branches to be up to date before merge;
- block force pushes;
- block branch deletion;
- apply the same bypass actors and bypass mode as `main`.

## Publishing contract

- A push to `main` publishes `latest` and the commit-SHA tag.
- A push to `release/vX.Y.Z` publishes `vX.Y.Z-rc` and the commit-SHA tag. It never publishes `latest`.
- A pushed `vX.Y.Z` tag publishes `vX.Y.Z` and the commit-SHA tag only when the tagged commit is reachable from either `main` or the exact matching branch `release/vX.Y.Z`.
- Tags from ordinary feature branches fail before registry authentication and image upload.

Before creating a release tag, verify the matching protected release branch exists or that the release commit has already reached `main`.
