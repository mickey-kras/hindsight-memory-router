# Releases

## Run a release

1. Merge the intended version bumps and code into `main`.
2. **Actions → main → Run workflow → main**. Check **Create a pinned release branch and automatically release after checks**.
3. Main passes, including Sonar → `release/X.Y.Z` freezes inputs → release gates pass → publish artifacts and immutable `vX.Y.Z` → promote `latest`.

The checkbox authorizes publication; there is no second button. Normal main runs never publish.
Preparation pauses Dependabot auto-merge for the full run. Avoid manual merges until it finishes.
The release includes the main SHA selected at dispatch, shown in the run summary. If main advances
before branch creation, rerun from current main. Only automation creates release branches and tags.

## Versions and inputs

| Component | Version source | Initial version |
| --- | --- | --- |
| Router | `release-version.json` and `pyproject.toml` | `0.1.0` |
| OpenClaw | root `package.json` | `0.12.0` |
| Coding agents | `src/upstream/coding-agents/package.json` | `0.6.0` |
| Integrations manifest/tag | integrations `release-version.json` | `0.1.0` |

Versions advance independently. Use plain SemVer; below 1.0, minor means breaking and patch means
compatible fixes. Review bumps on main, refresh locks/provenance, and rebuild changed packages.
Published package versions can be reused only with identical bytes. Failed preparation reserves its version.

Release router first. Integrations requires its latest immutable release with the same Hindsight pin.
`release.json` identifies the exact tested combination: package versions/checksums, router commit/digests,
Hindsight, upstream integration provenance, and `nix-openclaw` commit. Matching version numbers do not
imply compatibility. The Nix pin is deployment metadata; CI does not launch every coding harness or Nix OpenClaw.

Router main resolves latest stable Hindsight once for its checks; preparation freezes a fresh resolution.
Release runs keep frozen pins. Ordinary integration PRs use the reviewed router/Hindsight pins in
`.github/scripts/combination.cjs`; release PRs use `release.json`. The required combination smoke runs
packaged OpenClaw retain/recall and the packaged Codex hook against real router/Hindsight and a test LLM.

Router publishes the tested Linux amd64 image to GHCR/Docker Hub, signs/attests its digest and records
`image-digests.txt`. Integrations publishes tarballs, checksums and provenance to GitHub, without npm or
Docker publication. `latest` tracks the highest released version; older-line fixes cannot move it backwards.

## One-time setup, both repositories

1. Merge reviewed automation through existing gates. Integrations may need an owner-reviewed policy
   bootstrap. Keep the guard enabled; never fabricate statuses or give the release App a guard bypass.
2. Create a dedicated GitHub App installed only here: **Contents read/write**, implicit Metadata read,
   **no Administration**. Create environment **release-automation**, restricted to `main` and `release/*`.
   Add environment secret `RELEASE_APP_PRIVATE_KEY`, repository variable `RELEASE_APP_ID`, and no environment reviewers.
3. Generate ruleset import files:

   ```sh
   node .github/scripts/release-settings.cjs YOUR_NUMERIC_APP_ID /tmp/release-rulesets
   ```

4. In **Settings → Rules → Rulesets**, import/update all four generated rulesets. Only the two creation
   rules permit the App bypass. Release branch/tag protections have no bypass. Keep main protections
   and **Enforce release tag names** accepting `vX.Y.Z`; exclude `refs/heads/release/*` from work-branch naming.
5. Enable **immutable releases**. Review all bypass actors in Settings, then use your owner `gh` login:

   ```sh
   node .github/scripts/release-settings.cjs --review-immutable-settings YOUR_NUMERIC_APP_ID OWNER/REPO
   ```

   Save the JSON as environment variable `RELEASE_SETTINGS_REVIEW` in **release-automation**.
   The flag confirms your manual immutable-setting check. Preflight rejects redacted bypass actors
   without this review, and rejects changed ruleset revisions. Recheck settings and regenerate after changes.
6. Router: confirm `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` and Actions access to GHCR. Protect registry
   version/commit tags where supported; leave `latest` mutable. Git tag rules do not protect registry tags.
7. Run main, release router, then integrations. Verify manifests, immutable releases and registry digests.

Release fix PRs assume a single maintainer: zero required approvals, owner-reviewed squash merges.
Require independent approval before granting another person write access. CODEOWNERS cannot provide
self-approval. Sonar stays main-only by design; release tests, CodeQL, Aislop and Trivy remain required.

## Recovery

- **Checks fail:** open a `fix/...` PR against the release branch; squash after checks. Other PRs targeting
  that release branch refresh automatically. Forward-port code fixes to main. Keep pins and `.github/` unchanged.
- **Package fix:** bump that package if necessary, rebuild, update checksum/Nix files and its `release.json` entry.
- **Different pins/automation:** prepare a new version from main.
- **Upload/signing/alias failure:** **Re-run failed jobs**. Existing tags/assets must match. Router retains
  the tested image for 30 days and repeats smoke/scanning on retry. Never overwrite published bytes.
- **Bytes must change after publication began, or saved image expired:** use a new version.
- **Released:** retain the branch/tag. Future releases use another version.

Avoid merging release fixes during publication. GitHub and the registries do not publish atomically;
use recorded digests while recovering a partial publication.
