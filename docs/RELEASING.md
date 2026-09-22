# Releases

## Run a release

1. Merge the intended version bumps and code into `main`.
2. **Actions → main → Run workflow → main**. Check **Create a pinned release branch and automatically release after checks**.
3. Main passes, including Sonar → `release/X.Y.Z` freezes inputs → release gates pass → publish artifacts and immutable `vX.Y.Z` → promote `latest`.

The checkbox authorizes publication; there is no second button. Normal main runs never publish.
After publication the automation opens a next-patch version PR and enables squash auto-merge
after required checks pass. Retries verify the PR still contains only that version bump.
Both PR creation and later branch updates use the Release App so GitHub starts required PR checks
without the approval required for `GITHUB_TOKEN` updates. The App has no workflow-write permission;
the updater reports denied workflow-file updates as failures requiring a maintainer rebase.
After the bump PR is queued successfully, it deletes the published `release/X.Y.Z` branch,
plus older `release/*` branches still at their immutable published tags. A branch that advanced past its tag is kept and reported in the run summary.
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
Published package versions can be reused only with identical bytes. A created release branch reserves its
version, including after failure or cancellation. Failure before branch creation does not reserve a version.

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
- **Credentials/upload/signing/alias failure:** fix the cause, then **Re-run failed jobs** on the release
  run. The candidate branch stays available. Alternatively, run main with **Create release** from the
  same main snapshot: automation validates the existing candidate and requests its failed jobs again.
  Active runs are linked without starting a duplicate. A cancelled release is retried only by an explicit
  rerun or another Create release request; cancellation never schedules a retry by itself.
- **Partial publication:** router restores the tested image and original release asset bytes from the
  same run's retained artifacts, including the UI signature bundle, then repeats smoke/scanning. It
  verifies existing tags/assets match. Missing retained bytes after publication began fail closed.
- **Version-bump follow-up failure:** **Re-run failed jobs**. The published branch remains until the bump
  PR is queued successfully; retries reuse the PR and leave required checks in force.
- **Bytes must change after publication began, or saved image expired:** use a new version.
- **Released:** the branch is deleted automatically; the tag and immutable release stay. Future
  releases use another version.

Avoid merging release fixes during publication. GitHub and the registries do not publish atomically;
use recorded digests while recovering a partial publication.

### Failed release cleanup

Failure cleanup retains prepared branches so release-automation can resume the exact candidate. Failed
preparation also retains any branch it already created. Recovery never replaces a newer branch head,
changes frozen pins, or silently publishes another main snapshot. If main has advanced, rerun the
existing release workflow directly; use a new version for different code, pins, or automation.

Registry cleanup remains scoped to unpublished version/commit tags and their signing/attestation
artifacts. It preserves `latest`, other versions, tags owned by a newer digest, and every image referenced
by an existing Git tag or release. It reports cleanup errors without hiding the original failure.
The saved tested image remains available for retry for 30 days.

Cancellation preserves the candidate and registry state. Do not delete them to recover: explicitly rerun
the cancelled release, or request Create release again from the same main snapshot.

If GitHub starts a rerun after successful branch cleanup, preflight accepts the absent branch only when
its immutable release and tag identify the exact commit; original retained bytes are still required.
This does not guarantee GitHub can start a workflow whose branch was deleted.

A caller startup failure can prevent all jobs from running. If no release workflow exists for a prepared
branch, preparation reports that missing run instead of creating another candidate or claiming publication
succeeded. Resolve the workflow startup problem before retrying.
