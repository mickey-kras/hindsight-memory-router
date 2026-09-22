# Releases

## Run a release

1. Merge the intended version bumps and code into `main`.
2. **Actions → main → Run workflow → main**. Check **Create a pinned release branch and automatically release after checks**.
3. Main passes, including Sonar → `release/X.Y.Z` freezes inputs → release gates pass → publish artifacts and immutable `vX.Y.Z` → promote `latest`.

The checkbox authorizes publication; there is no second button. Normal main runs never publish.
After publication the automation opens a next-patch version PR and enables squash auto-merge
after required checks pass. Retries verify the PR still contains only that version bump. It deletes the published `release/X.Y.Z` branch, plus any earlier `release/*` branch still at its
published tag. A branch that advanced past its tag is kept and reported in the run summary.
Preparation pauses Dependabot auto-merge for the full run. Avoid manual merges until it finishes.
The release includes the main SHA selected at dispatch, shown in the run summary. If main advances
before branch creation, rerun from current main. Only automation creates release branches and tags.
Release tags are lightweight and unsigned by design. Their trust basis is the immutable GitHub
release plus cosign signatures and Rekor attestation records on the published digests; verify
artifacts by recorded digest, not by tag.

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
`image-digests.txt`. It then builds a CycloneDX SBOM from the pushed digest, normalizes it for
reproducible bytes, attests it to both registries as an OCI referrer, attaches it to the GitHub release
as `sbom.cdx.json`, and records its checksum as `sbom=` in `image-digests.txt`. It also builds the
quarantine UI package (`npm pack` in `ui/`), signs the tarball keyless with cosign sign-blob, attaches
`memory-router-ui-<version>.tgz` and its `.sigstore.json` bundle to the release, and records the tarball
checksum as `ui-package=` in `image-digests.txt`. The UI version comes from `ui/package.json`; bump it
when the consumed admin API contract changes. Integrations publishes
tarballs, checksums and provenance to GitHub, without npm or
Docker publication. `latest` tracks the highest released version; older-line fixes cannot move it backwards.

Pull requests run dependency review. Dependencies a PR adds or updates fail the check on HIGH or CRITICAL
advisories or on a forbidden license (`.github/dependency-review-config.yml`). Existing dependencies are
grandfathered; reviewed exceptions go into `allow-dependencies-licenses` as exact package URLs.

## One-time setup, both repositories

1. Merge reviewed automation through existing gates. Integrations may need an owner-reviewed policy
   bootstrap. Keep the guard enabled; never fabricate statuses or give the release App a guard bypass.
2. Create a dedicated GitHub App installed only here: **Contents read/write**, **Pull requests read/write**,
   implicit Metadata read, **no Administration**. Create environment **release-automation**, restricted to `main` and `release/*`.
   Add environment secret `RELEASE_APP_PRIVATE_KEY`, repository variable `RELEASE_APP_ID`, and no environment reviewers.
3. Generate ruleset import files:

   ```sh
   node .github/scripts/release-settings.cjs YOUR_NUMERIC_APP_ID /tmp/release-rulesets
   ```

4. In **Settings → Rules → Rulesets**, import/update all five generated rulesets. Only the creation
   rules and the deletion-only **Release branch deletion** rule permit the App bypass. Release
   branch/tag protections have no bypass. Keep main protections
   and **Enforce release tag names** accepting `vX.Y.Z`; exclude `refs/heads/release/*` from work-branch naming.
   After import, confirm every rule shows in Settings; the template uses preview rule types like
   copilot_code_review, so re-import or adjust before relying on this runbook.
5. Enable **immutable releases**. Review all bypass actors in Settings, then use your owner `gh` login:

   ```sh
   node .github/scripts/release-settings.cjs --review-immutable-settings YOUR_NUMERIC_APP_ID OWNER/REPO
   ```

   Save the JSON as environment variable `RELEASE_SETTINGS_REVIEW` in **release-automation**.
   The flag confirms your manual immutable-setting check. Preflight rejects redacted bypass actors
   without this review, and rejects changed ruleset revisions. Recheck settings and regenerate after changes.
6. Router: confirm `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` and Actions access to GHCR. Enable the
   Dependency graph (Settings → Code security) so PR dependency review works. Protect registry
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
- **Released:** the branch is deleted automatically; the tag and immutable release stay. Future
  releases use another version.

Avoid merging release fixes during publication. GitHub and the registries do not publish atomically;
use recorded digests while recovering a partial publication.

### Failed release cleanup

When a release run fails before the immutable release is finalized, the **clean up failed release** job
removes the run's leftovers automatically and posts a summary of what it deleted:

- the GHCR and Docker Hub tags the run pushed — exactly the version tag and the commit-sha tag, plus the
  cosign signature/attestation artifacts of this run's digest. `latest` and every other version are never
  touched. If the run's digest is known, tags that meanwhile moved to another digest (a newer attempt)
  are left alone;
- the `release/X.Y.Z` branch, deleted with the release App token (the App is the only bypass actor on the
  deletion ruleset). The branch is kept when it advanced past the failed run or when `vX.Y.Z` already
  exists — in that case re-run the failed jobs to finish the release instead.

A failed preparation dispatch also runs cleanup, deleting only the `release/*` branches its own run created.

Cleanup is idempotent, runs only on release branches after a failure, never on main or on success, and its
own failures cannot mask the original failure. It assumes the single-arch (Linux amd64) image the publish
job pushes; a multi-arch image would also leave the untagged per-arch child manifests behind. Abandon a
failed release by simply not re-running it; the version stays reserved, so the next release uses a new
version number.

Manual edge cases that still need the owner:

- **Startup failures:** when the caller workflow itself fails to start (no jobs execute, e.g. an invalid
  workflow or unresolvable secret), no cleanup job can run. Delete the orphaned branch with the release
  App and any pushed registry tags by hand.
- **Cleanup job failures** (e.g. a registry API outage): the job summary names what remains; delete it
  manually, then re-run the failed release jobs if the release should proceed.
- **Manual cancellation:** cancelling a run after it pushed and signed registry tags but before finalize
  leaves signed orphans behind. Cleanup intentionally skips `cancelled` runs (it triggers on `failure`
  results only), so delete the orphaned tags and the release branch by hand.
