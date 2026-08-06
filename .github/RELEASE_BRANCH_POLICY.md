# Protected release branches

Use `release/vX.Y.Z` for future-version work.

Apply the same GitHub ruleset to `main` and `release/v*`:

- pull requests only;
- same approvals, required checks, resolved conversations, and up-to-date requirement;
- same bypass actors;
- no force pushes or branch deletion.

Publishing:

- `main` → `latest` + commit SHA;
- `release/vX.Y.Z` → `vX.Y.Z-rc` + commit SHA;
- `vX.Y.Z` tag → stable image only when the commit is reachable from `main` or `release/vX.Y.Z`;
- all other refs → no publish.
