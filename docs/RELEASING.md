# Releases

## Run a release

1. Merge the intended version bumps and code into `main`.
2. **Actions → release → Run workflow → main**.
3. In that one run, main passes including Sonar → preparation freezes `release/X.Y.Z` → the candidate passes all release gates → images, signatures, attestations and immutable `vX.Y.Z` publish → `latest` promotes → the next-patch PR is queued and the published branch is removed.

The release workflow is the publication entry point. `main` runs automatically on pushes, or through
its inputless validation dispatch, and never publishes. The former **Create release** checkbox on
`main` is removed. Creating or updating a new release branch does not start another publication run.
Release dispatches from any branch other than `main`
fail at the entry guard, before validation, candidate checkout or release credentials are used.

The workflow graph contains separate main and candidate validation stages. Candidate jobs explicitly
check out and scan the frozen candidate SHA; the GitHub workflow source remains the selected dispatch
SHA. Sonar and Pages run only in the main stage. The run summary records candidate
and baseline commits. If main advances before creating a new candidate, dispatch from current main.
Native retries keep the original selected snapshot even if main later advances. If main has advanced,
use the original run’s retry button; a new dispatch does not select an older main snapshot.

After publication the automation opens a next-patch version PR and enables squash auto-merge
after required checks pass. Retries verify the PR still contains only that version bump.
Both PR creation and later branch updates use the Release App so GitHub starts required PR checks
without the approval required for `GITHUB_TOKEN` updates. The App has no workflow-write permission;
the updater reports denied workflow-file updates as failures requiring a maintainer rebase.
After the bump PR is queued successfully, automation deletes the published `release/X.Y.Z` branch,
plus older release branches still at their immutable published tags. Advanced branches are retained.
The single release run pauses Dependabot auto-merge through publication and follow-up. Avoid manual
merges until it finishes. Only automation creates release branches and tags.

Release tags are lightweight and unsigned. Verify artifacts by recorded digest using the immutable
GitHub release and cosign signatures. The reusable signing workflow remains `publish.yml`; a release
started on main has its actual main workflow identity. Image SLSA provenance preserves that source
and adds a `release-candidate` resolved dependency naming the release ref and exact candidate commit.
Check that dependency against the release tag and `image-digests.txt`. The official `@actions/attest`
builder constructs the workflow claims; the pinned `@sigstore/core` override fixes its transitive
DSSE advisory without replacing GitHub's signing actions.

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
7. Verify main CI, dispatch the router release workflow, then release integrations. Verify manifests, immutable releases and registry digests.

Release fix PRs assume a single maintainer: zero required approvals, owner-reviewed squash merges.
Require independent approval before granting another person write access. CODEOWNERS cannot provide
self-approval. Sonar stays main-only by design; release tests, CodeQL, Aislop and Trivy remain required.

## Recovery

- **Code checks fail:** fix the code through a PR to main. If a candidate already reserved the version,
  choose a new version on main and dispatch release again. New release candidates always originate
  from reviewed main; changing a retained candidate is not a retry.
- **Package fix:** update the package and its version on main. If a candidate already exists, prepare
  a new release version for the changed bytes.
- **Different pins/automation:** prepare a new version from main.
- **Credentials/upload/signing/alias failure:** fix the cause, then **Re-run failed jobs** on the original
  release run. A repeated dispatch from the same main snapshot links and requests that original run's
  native retry; it does not prepare another candidate. Active and successful runs are linked without
  duplication. This recovery redirect is explicit in the new run summary; there is no polling workflow.
- **Cancelled:** use **Re-run all jobs** on the original release run, or explicitly dispatch release
  again from the same snapshot. Cancellation preserves state and never schedules a retry or failure issue.
- **Partial publication:** router restores the tested image and original release assets from the same
  run's retained artifacts, including the UI signature bundle, then repeats smoke/scanning. Existing
  tags/assets must match. Missing retained bytes after publication began fail closed.
- **Version-bump follow-up failure:** **Re-run failed jobs**. The branch remains until the bump PR is
  queued; retries reuse that PR and retain required checks.
- **Bytes must change after publication began, or saved image expired:** use a new version.
- **Released:** the branch is deleted automatically; the tag and immutable release stay. A native full
  rerun of the unified main dispatch can recover that exact candidate from its published tag, even
  after main has advanced to the next development version. Original retained bytes remain required.

Avoid merging release fixes during publication. GitHub and registries do not publish atomically;
use recorded digests while recovering a partial publication.

### Cleanup and older runs

Failure cleanup retains prepared branches, including a branch created before preparation lost its
acknowledgement. Registry cleanup remains scoped to unpublished version/commit tags and their signing
and attestation artifacts. It preserves `latest`, other versions, tags owned by a newer digest, and
images referenced by any existing Git tag or release. Cleanup errors do not hide the original failure.
The tested image remains available for retry for 30 days. Cancellation leaves candidate and registry
state available for an explicit retry.

Existing releases and branches prepared before consolidation keep their frozen automation. Recover
those through their original push-triggered release run; repeated preparation recognizes their legacy
run identity. They are not silently migrated to the new dispatch pipeline. If GitHub cannot start an
old run after its branch was deleted, use a new version; the new main-dispatch recovery does not change
GitHub's startup behavior for old workflows. A missing originating run is reported as a failure.

Integrations release automation is unchanged by this router workflow consolidation.
