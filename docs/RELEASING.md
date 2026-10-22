# Releases

[Documentation](README.md) | [Repository](../README.md)

## Run a release

1. Merge the intended version bumps and code into `main`.
2. **Actions > release > Run workflow > main**.
3. The run validates main, including Sonar, and freezes `release/X.Y.Z`. After the candidate passes all release gates, it publishes images, signatures, attestations and immutable `vX.Y.Z`, promotes `latest`, queues the next-patch PR and removes the published branch.

The release workflow is the publication entry point. `main` runs automatically on pushes, or through
its inputless validation dispatch, and never publishes. The former **Create release** checkbox on
`main` is removed. Creating or updating a new release branch does not start another publication run.
Release dispatches from any branch other than `main`
fail at the entry guard, before validation, candidate checkout or release credentials are used.

The workflow graph contains separate main and candidate validation stages. Candidate jobs explicitly
check out and scan the frozen candidate SHA; the GitHub workflow source remains the selected dispatch
SHA. The release baseline retains Sonar and architecture validation. Pages publication and PR branch
updates run in ordinary main workflows and are omitted from the release baseline. The run summary
records candidate and baseline commits. If main advances before creating a new candidate, dispatch from current main.
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
Check that dependency against the release tag and `image-digests.txt`. The provenance helper verifies
GitHub OIDC signatures and binds the claims to the executing workflow. Cosign signs provenance and
CycloneDX predicates for each registry digest. Publication requires local bundle and registry
verification, GitHub attestation upload, and GitHub CLI verification through repository discovery.
Verified Sigstore bundles are retained as workflow artifacts.

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
`mickey-kras-memory-router-ui-<version>.tgz` and its `.sigstore.json` bundle to the release, and records the tarball
checksum as `ui-package=` in `image-digests.txt`. The UI version comes from `ui/package.json`; bump it
whenever packaged bytes change, including metadata and documentation. After verifying the
immutable GitHub assets and UI signature, the workflow publishes that exact tarball to public npm
as `@mickey-kras/memory-router-ui`, with OIDC and provenance, without rebuilding or repacking.
Retries require matching npm SHA-512 integrity and provenance. Integration package publication is
described in that repository's release guide. `latest` tracks the highest released version; older-line fixes cannot move it backwards.

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

4. In **Settings > Rules > Rulesets**, import/update all five generated rulesets. Only the creation
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
   Dependency graph (Settings > Code security) so PR dependency review works. Protect registry
   version/commit tags where supported; leave `latest` mutable. Git tag rules do not protect registry tags.
7. Verify main CI, dispatch the router release workflow, then release integrations. Verify manifests, immutable releases and registry digests.

Release fix PRs use the independent implementation App and owner-reviewed squash merges.
After the CI owner-review ruleset is activated, every fix PR requires an approval,
including approval of the latest push by someone other than its pusher. CI changes
also require the designated code owner; follow the activation procedure below. Dry-run
and release gates remain mandatory. Sonar stays main-only by design; release tests,
CodeQL, Aislop and Trivy remain required.

## npm first publication

[Trusted publishing requirements](https://docs.npmjs.com/trusted-publishers/):
GitHub-hosted runner, Node >=22.14, npm >=11.5.1, `id-token: write`, public repository/package.
The workflow pins its npm CLI and uses no npm token secret.

1. If the scoped package does not exist, publish a bootstrap version from a disposable checkout.
   Set `ui/package.json` and its lockfile to an unused version lower than the intended release
   (for example `0.0.0`), build and pack with `npm ci --prefix ui` and
   `npm pack ./ui --pack-destination .`. Use `npm login` locally, then
   `npm publish ./mickey-kras-memory-router-ui-0.0.0.tgz --access public --ignore-scripts --tag bootstrap`.
   Keep bootstrap edits out of main. This setup version has no CI provenance and is not a release;
   never use the intended release version for it, since npm versions cannot be overwritten.
2. In npm package **Settings > Trusted publishing**, add GitHub Actions:

   | Field | Value |
   | --- | --- |
   | Owner | `mickey-kras` |
   | Repository | `hindsight-memory-router` |
   | Workflow filename | `release.yml` |
   | Environment | `release-automation` |
   | Allowed action | Direct `npm publish` |

   npm checks the caller `release.yml`; cosign's signing identity is the reusable `publish.yml`.
   Restrict publishing access to require 2FA and disallow tokens. Newly configured trust must
   complete a publish within npm's configuration expiry window.
3. Dispatch **release** from main. The intended UI version must be unused, or already have
   identical bytes and provenance. npm publication failure retains the candidate and skips
   version-bump/branch-deletion follow-up; rerun failed jobs after correcting npm setup.
4. Confirm `npm view @mickey-kras/memory-router-ui@<version> dist --json` reports integrity and
   provenance. Download with `npm pack @mickey-kras/memory-router-ui@<version> --ignore-scripts`,
   compare SHA-256 with `ui-package=` in the GitHub release's `image-digests.txt`, and verify
   the signature using [the UI instructions](../ui/README.md#package).

Do not mark first publication complete until installation/download, integrity and provenance
are verified against the actual public registry. A manually published release version without
provenance requires a new UI version; the retry check does not bypass provenance.

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

## CI policy admission

The `policy` workflow runs from the trusted base with `pull_request_target`, reads
candidate files through the GitHub API, and never checks out or executes PR code.
The YAML parser is installed with lifecycle scripts disabled from a sparse checkout
of `.github/scripts` at the immutable executing `github.workflow_sha`; it never
loads the candidate manifest, lockfile or parser.
Its required check remains `guard / guard`. Do not call the guard from a candidate
`pull_request` workflow: that lets the candidate replace its own validator.

CI lockfiles are data, not an admission ledger. `.github/scripts/package-lock.json`
is checked as npm lockfile version 3: every dependency needs an HTTPS tarball from
exactly `registry.npmjs.org` matching its package name and version, plus canonical
SHA-512 integrity. Linked, bundled and nested-shrinkwrap packages are rejected, and no package may acquire an install script relative to
the immutable base lockfile. The root dependency declarations must match the
separately gated `package.json`. These checks establish source and installation
constraints, not that registry content is trustworthy or vulnerability-free;
required dependency-review, audit and other CI checks still apply. Changes to
`.npmrc` in the repository root, `.github`, or `.github/scripts`, and a shadow
`.github/scripts/npm-shrinkwrap.json`, are forbidden even when the lockfile itself
is unchanged. They could redirect registry requests or replace the checked lock. A routine
lockfile refresh never requires changing the guard's hashes. Do not restore a
lockfile hash allowlist or admit an old vulnerable lockfile to unblock a release.

Executable workflows/helpers and security configuration retain a single reviewed
hash per path. Updating an admission replaces the existing hash; it never appends
an older version. Policy source itself must equal the trusted base or receive the
same independent review as an unknown code hash. A hash mismatch can be admitted
in the same PR only when all of these conditions hold:

- The PR author is a GitHub App bot (`type: Bot`), separate from the owner.
  A machine-user account has `type: User` and cannot activate this admission path.
- The base branch's `.github/CODEOWNERS` assigns `/.github/` to `@mickey-kras`.
- Live effective branch rules require code-owner approval, at least one approval,
  dismissal of stale approvals, and approval of the most recent push by someone
  other than its pusher.
- The owner's latest decisive review is `APPROVED` for the exact current head SHA.
  A later change request or dismissal invalidates it. API errors fail the guard.

Approval only admits the changed code hash. It cannot override workflow security
checks, malformed lockfiles, removal protection or the required CI suite. Protected
workflows must preserve their immutable-base execution contract: existing jobs,
job dependencies and conditions, and existing steps (including commands, action
targets, inputs, environment and failure handling). Action commit pins may refresh.
Independent owner review can admit supplementary jobs or steps in the same PR;
existing steps must remain in order. Reviewers must check that additions do not
undermine existing gates. Removing or changing mandatory controls needs an explicit
trusted-policy migration, not an ordinary hash approval. After
approval, rerun the failed trusted-base `policy` job. A subsequent push needs a new
approval and run; native rules enforce review dismissal even after a green job.
Human review and agent-generated code must never share the owner credential.

### One-time administrative activation

1. Create/install a separate implementer GitHub App
   with repository contents, pull-request and workflow write access only as needed.
   Keep administration, review approval and release credentials out of that
   identity. Configure the implementer connection to use it; verify a test PR is
   authored by that bot and the human owner performs the review independently.
2. Add `.github/CODEOWNERS` and import
   `.github/rulesets/require-ci-owner-review.json` as an **additional active**
   ruleset for the default and release branches. Keep existing status checks,
   protections and bypass restrictions. A JSON file in Git is not a deployed rule.
   This template requires one review for every PR and code-owner approval for CI
   files. Do not add the implementer to a bypass list.
3. Verify the live rule through `GET /repos/{owner}/{repo}/rules/branches/{branch}`,
   then exercise a bot-authored policy PR: no review must fail; approval of the
   exact head must pass; a later push or dismissed review must block merging.
4. Merge the migration through the existing protected process. If the old guard
   cannot admit the migration, the owner must record the exact reviewed head,
   evidence, inherited failures and explicitly authorized one-time bootstrap
   exception in that PR. Never fake checks or introduce a standing bypass.

Until the independent bot and live rules are installed, same-PR review admission
fails closed. The repository files cannot create the App, change the connection's
identity, or activate repository rulesets. After activation, use the single-PR
review path instead of paired hash-admission PRs or owner bypasses. This mechanism
removes repetitive lockfile approvals without making registry integrity a
substitute for human approval of code that executes.
