# Releases

[Documentation](README.md) | [Repository](../README.md)

## Run a release

1. Merge the intended version changes and code into `main`.
2. Select **Actions > release > Run workflow > main**.
3. The run validates main, including Sonar, and freezes `release/X.Y.Z`.
   After the candidate passes all release gates, the run publishes images, signatures, attestations and the immutable release `vX.Y.Z`.
   It promotes `latest`.
   It queues the next-patch PR.
   It removes the published branch.

The release workflow is the publication entry point.
`main` runs automatically on pushes or through its validation dispatch without inputs.
It never publishes.
The `main` workflow no longer has the former **Create release** checkbox.
Creating or updating a new release branch does not start another publication run.

A release dispatch from a branch other than `main` fails at the entry guard.
This occurs before validation, candidate checkout, or release credential use.

The workflow graph has separate main and candidate validation stages.
Candidate jobs clone and scan the frozen candidate SHA.
The GitHub workflow source stays the selected dispatch SHA.
The release baseline keeps Sonar and architecture validation.
Pages publication and PR branch updates run in ordinary main workflows.
The release baseline excludes these jobs.

The summary of the run records the candidate and baseline commits.
If main advances before creation of a new candidate, dispatch from current main.
Native retries keep the original selected snapshot even if main advances later.
If main advanced, use the retry button of the original run.
A new dispatch does not select an older main snapshot.

After publication, automation opens a PR for the next patch version.
It enables squash auto-merge after required checks pass.
Retries make sure that the PR contains only that version change.
PR creation and later branch updates use the Release App.
This lets GitHub start required PR checks without the approval that `GITHUB_TOKEN` updates must have.
The App has no workflow-write permission.

The updater reports denied workflow-file updates as failures. A maintainer must rebase them.
After automation queues the version PR, it deletes the published `release/X.Y.Z` branch.
It also deletes older release branches still at their immutable published tags.
It keeps advanced branches.
The single release run pauses Dependabot auto-merge through publication and the steps after it.

Avoid manual merges until the run finishes.
Only automation creates release branches and tags.

The release tags are lightweight and unsigned.
Examine the artifacts by their recorded digest. Compare them with the immutable GitHub release and the cosign signatures.
The reusable signing workflow is `publish.yml`.

A release started on main has its actual main workflow identity.
The SLSA provenance of the image keeps that source.
It adds a `release-candidate` resolved dependency that names the release ref and exact candidate commit.

Check that dependency against the release tag and `image-digests.txt`.
The provenance helper examines GitHub OIDC signatures and binds claims to the executing workflow.
Cosign signs provenance and CycloneDX predicates for each registry digest.
Before publication, the workflow examines the local bundle and the registry, uploads the GitHub attestation, and examines it with the GitHub CLI through repository discovery.
Workflow artifacts keep the examined Sigstore bundles.

## Versions and inputs

| Part | Version source | Initial version |
| --- | --- | --- |
| Router | `release-version.json` and `pyproject.toml` | `0.1.0` |
| OpenClaw | root `package.json` | `0.12.0` |
| Coding agents | `src/upstream/coding-agents/package.json` | `0.6.0` |
| Integrations manifest and tag | integrations `release-version.json` | `0.1.0` |

Versions advance independently.
Use plain SemVer.
Below 1.0, minor versions show breaking changes and patch versions show compatible fixes.
Review version changes on main.
Refresh the locks and the provenance.
Rebuild changed packages.

You can use a published package version again only with the same bytes.
A created release branch reserves its version, including after failure or cancellation.
Failure before branch creation does not reserve a version.

Release the router first.
Integrations must have the latest immutable release of the router with the same Hindsight pin.
`release.json` identifies the exact tested combination.
It records package versions and checksums, the router commit and digests, Hindsight, upstream integration provenance, and the `nix-openclaw` commit.
Matching version numbers do not imply compatibility.
The Nix pin is deployment metadata.

CI does not launch every coding harness or Nix OpenClaw.

Router main resolves the latest stable Hindsight one time for its checks. Preparation freezes a new resolution.

The release runs keep frozen pins. Ordinary integration PRs use the reviewed router and Hindsight pins in
`.github/scripts/combination.cjs`. Release PRs use `release.json`. The required combination smoke
tests the packaged OpenClaw retain and recall. It also tests the packaged Codex hook with a real router, Hindsight and a test LLM.

The router publishes the tested Linux amd64 image to GHCR and Docker Hub.
It signs and attests the digest and records `image-digests.txt`.
It builds a CycloneDX SBOM from the pushed digest.
It normalizes the SBOM for reproducible bytes.
It attests the SBOM to both registries as an OCI referrer.

The workflow attaches the SBOM to the GitHub release as `sbom.cdx.json`.
It records the checksum as `sbom=` in `image-digests.txt`.
It builds the quarantine UI package with `npm pack` in `ui/`.
It signs the tarball keyless with cosign sign-blob.
It attaches `mickey-kras-memory-router-ui-<version>.tgz` and its `.sigstore.json` bundle to the release.
It records the tarball checksum as `ui-package=` in `image-digests.txt`.

The UI version comes from `ui/package.json`.
Increase it whenever packaged bytes change, including metadata and documentation.
The workflow examines the immutable GitHub assets and the UI signature.
It then publishes that exact tarball to public npm as `@mickey-kras/memory-router-ui`, with OIDC and provenance.
It does not rebuild or repack the tarball.
Retries must have the same npm SHA-512 integrity and provenance.

The integrations repository's release guide describes integration package publication.
`latest` tracks the highest released version.
Fixes for older version lines cannot move it backwards.

Each pull request runs a dependency review.
The check rejects added or updated dependencies with HIGH or CRITICAL advisories.
`.github/dependency-review-config.yml` enables vulnerability checks and disables automated license checks.
Review dependency licenses manually under the [dependency license policy](../SECURITY.md#dependency-licenses).
Existing dependencies do not prove license approval.

## One-time setup, both repositories

1. Merge reviewed automation through existing gates.
   Integrations can have an initial policy configuration that the owner must review.
   Keep the guard enabled.
   Never write false statuses.
   Never give the release App a guard bypass.
2. Create a dedicated GitHub App installed only here.
   Grant **Contents: Read and write**, **Pull requests: Read and write**, and the implicit **Metadata: Read**.
   Grant **no Administration** permission.
   Create environment **release-automation**, restricted to `main` and `release/*`.
   Add environment secret `RELEASE_APP_PRIVATE_KEY`.

   Add repository variable `RELEASE_APP_ID`.
   Configure no environment reviewers.
3. Generate the import files for the rulesets:

   ```sh
   node .github/scripts/release-settings.cjs YOUR_NUMERIC_APP_ID /tmp/release-rulesets
   ```

4. In **Settings > Rules > Rulesets**, import or update all five generated rulesets.
   Only the creation rules and the deletion-only **Release branch deletion** rule let the App bypass them.
   The protections of release branches and tags have no bypass.
   Keep main protections and **Enforce release tag names** accepting `vX.Y.Z`.
   Exclude `refs/heads/release/*` from work-branch naming.

   After import, confirm every rule appears in Settings.
   The template uses preview rule types such as copilot_code_review.
   Re-import or adjust missing rules before you rely on this procedure.
5. Enable **immutable releases**.
   Review all bypass actors in Settings.
   Run the following command with your owner `gh` login:

   ```sh
   node .github/scripts/release-settings.cjs --review-immutable-settings YOUR_NUMERIC_APP_ID OWNER/REPO
   ```

   Save the JSON as environment variable `RELEASE_SETTINGS_REVIEW` in **release-automation**.
   The flag confirms your manual immutable-setting check.
   Preflight rejects redacted bypass actors without this review.
   It also rejects changed ruleset revisions.
   Recheck settings after changes.
   Regenerate the review after changes.
6. For the router, confirm `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` and Actions access to GHCR.
   Enable the Dependency graph in **Settings > Code security** for PR dependency review.
   Protect the version and commit tags in each registry that supports it.
   Leave `latest` mutable.
   Git tag rules do not protect registry tags.
7. Examine the `main` CI.
   Dispatch the router release workflow.
   Release the integrations.
   Examine the manifests, the immutable releases and the registry digests.

Release fix PRs use the independent implementation App and owner-reviewed squash merges.
After activation of the CI review ruleset, every fix PR requires approval.
The person who approves the latest push must not be its pusher.
CI changes also require code-owner approval.
Follow the activation procedure below.
Dry-run and release checks stay mandatory.
Sonar runs only on `main` by design.
The release tests, CodeQL, Aislop and Trivy stay mandatory.

## npm first publication

[Trusted publishing requirements](https://docs.npmjs.com/trusted-publishers/):
GitHub-hosted runner, Node >=22.14, npm >=11.5.1, `id-token: write`, a public repository and a public package.
The workflow pins its npm CLI and uses no npm token secret.

1. If the scoped package does not exist, publish a bootstrap version from a disposable checkout.
   Set `ui/package.json` and its lockfile to an unused version lower than the intended release, for example `0.0.0`.
   Build with `npm ci --prefix ui`.
   Pack with `npm pack ./ui --pack-destination .`.
   Run `npm login` locally.

   Run `npm publish ./mickey-kras-memory-router-ui-0.0.0.tgz --access public --ignore-scripts --tag bootstrap`.

   Keep bootstrap edits out of main.
   This setup version has no CI provenance and is not a release.
   Never use the intended release version for setup.
   You cannot overwrite an npm version.
2. In npm package **Settings > Trusted publishing**, add GitHub Actions:

   | Field | Value |
   | --- | --- |
   | Owner | `mickey-kras` |
   | Repository | `hindsight-memory-router` |
   | Workflow filename | `release.yml` |
   | Environment | `release-automation` |
   | Allowed action | Direct `npm publish` |

   npm checks the caller `release.yml`.
   Cosign's signing identity is the reusable `publish.yml`.
   Restrict publication access to accounts with 2FA.
   Disallow tokens.
   Newly configured trust must complete a publish within npm's configuration expiry window.
3. Dispatch **release** from main.
   Use a new UI version, or a published UI version that has the same bytes and provenance.
   If npm publication fails, the run keeps the candidate and skips the version-bump and branch-deletion steps.
   After you correct npm setup, rerun failed jobs.
4. Confirm `npm view @mickey-kras/memory-router-ui@<version> dist --json` reports integrity and provenance.
   Download with `npm pack @mickey-kras/memory-router-ui@<version> --ignore-scripts`.
   Compare SHA-256 with `ui-package=` in the GitHub release's `image-digests.txt`.
   Examine the signature with [the UI instructions](../ui/README.md#package).

Examine the installation, download, integrity and provenance against the actual public registry before you mark first publication complete.
If you publish a release version manually without provenance, you must publish a new UI version.
The retry check does not bypass provenance.

## Recovery

- **Code checks fail:** Fix the code through a PR to main.
  If a candidate already reserved the version, choose a new version on main.
  Dispatch release again.
  New release candidates always originate from reviewed main.
  A change to a kept candidate is not a retry.
- **Package fix:** Update the package on main.
  Update its version.
  If a candidate already exists, prepare a new release version for the changed bytes.
- **Different pins or automation:** Prepare a new version from main.
- **Credential, upload, signing or alias failure:** Correct the cause.
  Select **Re-run failed jobs** on the original release run.
  A repeated dispatch from the same main snapshot links that original run and requests its native retry.
  It does not prepare another candidate.
  The summary links active and successful runs without duplication.
  The new run summary explicitly reports this recovery redirect.

  There is no polling workflow.
- **Canceled:** Select **Re-run all jobs** on the original release run.
  Alternatively, dispatch release again from the same snapshot.
  Cancellation preserves state and never schedules a retry or failure issue.
- **Partial publication:** The router restores the tested image and original release assets from the kept artifacts of the same run.
  These assets include the UI signature bundle.
  The router then repeats the smoke tests and the scans.
  Existing tags and assets must match.
  If kept bytes are missing after publication starts, the run fails and stops all publication.
- **Version-bump follow-up failure:** Select **Re-run failed jobs**.
  The branch stays until automation queues the version PR.
  Retries use that PR again and keep its required checks.
- **Bytes must change after publication began, or saved image expired:** Use a new version.
- **Released:** Automation deletes the branch.
  The tag and the immutable release stay.
  A native full rerun of the unified main dispatch can recover the exact candidate from its published tag.
  This works even after main advances to the next development version.
  The original kept bytes stay necessary.

Do not merge release fixes during publication. GitHub and the registries do not publish atomically.
Use the recorded digests to recover a partial publication.

### Cleanup and older runs

Failure cleanup keeps prepared branches, including a branch created before preparation lost its
acknowledgement. Registry cleanup stays scoped to unpublished version and commit tags and their signing
and attestation artifacts. It preserves `latest`, other versions, tags owned by a newer digest, and
images referenced by any existing Git tag or release. Cleanup errors do not hide the original failure.
The tested image stays available for a retry for 30 days. Cancellation leaves candidate and registry
state available for an explicit retry.

Existing releases and branches prepared before consolidation keep their frozen automation.
Recover them through their original push-triggered release run.
Repeated preparation recognizes their legacy run identity.
They do not automatically migrate to the new dispatch pipeline.
If GitHub cannot start an old run after branch deletion, use a new version.
The new main-dispatch recovery does not change GitHub's startup behavior for old workflows.

The workflow reports a missing originating run as a failure.

This consolidation of the router workflows does not change the release automation of the integrations.


## CI policy admission

The `policy` workflow runs from the trusted base with `pull_request_target`.
It reads candidate files through the GitHub API.
It never checks out or executes PR code.
The YAML parser comes from `.github/scripts` at the executing `github.workflow_sha`.
Its installation disables lifecycle scripts.
The guard never loads the candidate manifest, lockfile or parser.

The required check stays `guard / guard`.
Do not call the guard from a candidate `pull_request` workflow.
That would let the candidate replace its own validator.

### Lockfile checks

The guard checks `.github/scripts/package-lock.json` as npm lockfile version 3.
Each dependency must have these properties:

- An HTTPS tarball from exactly `registry.npmjs.org`.
- A tarball path that matches its package name and version.
- Canonical SHA-512 integrity.
- No new install script compared with the immutable base lockfile.

The guard rejects linked packages, bundled packages and nested shrinkwrap files.
The root dependency declarations must match the separately checked `package.json`.
These checks constrain the source and installation behavior.
They do not prove that registry content is safe or free from vulnerabilities.
Dependency review, audit and all other required CI checks still apply.

Changes to `.npmrc` in the repository root, `.github`, or `.github/scripts` are forbidden.
A shadow `.github/scripts/npm-shrinkwrap.json` is also forbidden.
This restriction applies when the checked lockfile has no changes.
These files could redirect registry requests or replace the checked lockfile.

A routine lockfile update does not require changes to the guard hashes.
Do not restore a lockfile hash allowlist.
Do not admit an old vulnerable lockfile to release a package.

### Code approval

Executable workflows, helpers and security configuration keep one reviewed hash per path.
Replace the existing hash when you update an admission.
Do not append an older version.
Policy source must equal the trusted base or receive the same independent review as an unknown code hash.

The guard can admit a new code hash in the same PR only when all these conditions apply:

- A GitHub App bot (`type: Bot`) is the PR author.
  It must be separate from the owner.
  A machine-user account has `type: User` and cannot use this approval path.
- The base branch's `.github/CODEOWNERS` assigns `/.github/` to `@mickey-kras`.
- Live branch rules require code-owner approval and at least one approval.
  They dismiss stale approvals.
  They require approval of the latest push by someone other than its pusher.
- The owner's latest decisive review is `APPROVED` for the exact current head SHA.
  A later change request or dismissal invalidates it.
  API errors cause the guard to fail.

Approval admits only the changed code hash.
It cannot override workflow security checks, malformed lockfiles, removal protection or required CI checks.
Protected workflows must keep their existing execution controls from the immutable base.
These include jobs, dependencies, conditions and the order of existing steps.
Existing commands, action targets, inputs, environment variables and failure handling must stay unchanged.
Action commit pins can change.

Independent owner review can admit additional jobs or steps in the same PR.
Reviewers must check that additions do not weaken existing checks.
Removal or change of mandatory controls requires an explicit trusted-policy migration.
Ordinary hash approval is not sufficient.

After approval, rerun the failed trusted-base `policy` job.
A subsequent push requires a new approval and run.
Native rules dismiss stale reviews even after a successful job.
Human review and agent-generated code must never use the same owner credential.

### One-time administrative activation

1. Create a separate implementation GitHub App.
   Install it in the repository.
   Give it only the necessary contents, pull-request and workflow write permissions.
   Keep administration, review approval and release credentials out of this identity.
   Configure the implementation connection to use the App.
   Verify that a test PR has that bot as its author.
   The human owner must review it independently.
2. Add `.github/CODEOWNERS`.
   Import `.github/rulesets/require-ci-owner-review.json` as an additional active ruleset for the default and release branches.
   Keep existing status checks, protections and bypass restrictions.
   A JSON file in Git does not activate a rule.
   This template requires one review for every PR and code-owner approval for CI files.
   Do not add the implementation App to a bypass list.
3. Verify the live rule through `GET /repos/{owner}/{repo}/rules/branches/{branch}`.
   Test a policy PR that the bot created.
   Without review, it must fail.
   Approval of the exact head must pass.
   A later push or dismissed review must prevent the merge.
4. Merge the migration through the existing protected process.
   If the old guard cannot admit the migration, the owner must record a one-time exception in that PR.
   Record the exact reviewed head, evidence and inherited failures.
   The owner must explicitly authorize this initial exception.
   Never write false check results or introduce a permanent bypass.

Until the independent bot and live rules are installed, same-PR code approval stays disabled.
Repository files cannot create the App, change the connection identity or activate rulesets.
After activation, use the single-PR review procedure.
Do not return to paired hash-admission PRs or owner bypasses.
Registry integrity does not replace human approval of executable code.
