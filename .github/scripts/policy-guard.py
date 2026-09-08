#!/usr/bin/env python3
"""PR policy guard for workflow and automation files.

Runs from the pull request base revision and inspects head files through the
GitHub API; contributor code is never checked out or executed.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

import yaml

WORKFLOWS_DIR = ".github/workflows"
PUBLISH = f"{WORKFLOWS_DIR}/publish.yml"
CI = f"{WORKFLOWS_DIR}/ci.yml"
CODEQL = f"{WORKFLOWS_DIR}/codeql.yml"
AISLOP = f"{WORKFLOWS_DIR}/aislop.yml"
NIGHTLY = f"{WORKFLOWS_DIR}/nightly.yml"
DEPENDABOT_WORKFLOW = f"{WORKFLOWS_DIR}/dependabot-auto-merge.yml"
GUARD_WORKFLOW = f"{WORKFLOWS_DIR}/policy-guard.yml"
DEPENDABOT_SCRIPT = ".github/scripts/dependabot-auto-merge.cjs"
FAILURE_REPORTER = ".github/scripts/upsert-main-failure-issue.sh"
SONAR_REPORTER = ".github/scripts/sync-sonar-findings.py"
GUARD_SCRIPT = ".github/scripts/policy-guard.py"
PACKAGE_JSON = "package.json"

PROTECTED = {
    PUBLISH,
    CI,
    CODEQL,
    AISLOP,
    NIGHTLY,
    DEPENDABOT_WORKFLOW,
    GUARD_WORKFLOW,
    DEPENDABOT_SCRIPT,
    FAILURE_REPORTER,
    SONAR_REPORTER,
    GUARD_SCRIPT,
}

PRIVILEGED_WRITE_KEYS = ("id-token", "packages", "attestations", "issues")
PRIVILEGED_ALLOWED = {PUBLISH, DEPENDABOT_WORKFLOW, NIGHTLY}
HEAD_TERMS = (
    "github.event.pull_request.head",
    "github.head_ref",
    "head.sha",
    "pull_request.head",
)
SHA_PIN = re.compile(r"@[0-9a-f]{40}$", re.IGNORECASE)
SARIF_CATEGORY = "category: .github/workflows/publish.yml"

failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


class GitHub:
    def __init__(self, repository: str, token: str) -> None:
        self.base = f"https://api.github.com/repos/{repository}"
        self.token = token

    def get(self, path: str, **params: str | int) -> Any:
        query = urllib.parse.urlencode({k: str(v) for k, v in params.items()})
        request = urllib.request.Request(  # noqa: S310 - fixed API host
            f"{self.base}{path}?{query}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return json.load(response)

    def pull_files(self, number: int) -> list[dict[str, Any]]:
        files: list[dict[str, Any]] = []
        page = 1
        while True:
            batch = self.get(f"/pulls/{number}/files", per_page=100, page=page)
            files.extend(batch)
            if len(batch) < 100:
                return files
            page += 1

    def file_at(self, path: str, ref: str) -> str | None:
        try:
            data = self.get(f"/contents/{urllib.parse.quote(path)}", ref=ref)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise
        if "content" not in data:
            return None
        return base64.b64decode(data["content"]).decode("utf-8")


def triggers(doc: dict[str, Any]) -> set[str]:
    # YAML 1.1 parses the bare key `on` as boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(item) for item in on}
    if isinstance(on, dict):
        return {str(key) for key in on}
    return set()


def permission_maps(doc: dict[str, Any]) -> list[Any]:
    maps = []
    if "permissions" in doc:
        maps.append(doc["permissions"])
    for job in (doc.get("jobs") or {}).values():
        if isinstance(job, dict) and "permissions" in job:
            maps.append(job["permissions"])
    return maps


def uses_references(doc: dict[str, Any]) -> list[str]:
    references = []
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            references.append(job["uses"])
        for step in job.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                references.append(step["uses"])
    return references


def step_names(doc: dict[str, Any], job_name: str) -> set[str]:
    job = (doc.get("jobs") or {}).get(job_name) or {}
    return {
        str(step["name"])
        for step in job.get("steps") or []
        if isinstance(step, dict) and "name" in step
    }


def load_workflow(text: str, path: str) -> dict[str, Any] | None:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as error:
        fail(f"{path}: workflow does not parse as YAML ({error})")
        return None
    if not isinstance(doc, dict):
        fail(f"{path}: workflow must be a YAML mapping")
        return None
    return doc


def check_workflow_basics(path: str, text: str) -> None:
    doc = load_workflow(text, path)
    if doc is None:
        return
    events = triggers(doc)
    for permissions in permission_maps(doc):
        if permissions == "write-all":
            fail(f"{path}: broad write permissions are not allowed")
            continue
        if not isinstance(permissions, dict):
            continue
        for key, value in permissions.items():
            if key in PRIVILEGED_WRITE_KEYS and value == "write":
                if path not in PRIVILEGED_ALLOWED:
                    fail(f"{path}: {key}: write is only allowed in trusted workflows")
                if "pull_request" in events:
                    fail(f"{path}: pull request workflows must not have {key}: write")
    if "pull_request_target" in events:
        checkouts = any(
            reference.startswith("actions/checkout@") for reference in uses_references(doc)
        )
        if checkouts and any(term in text for term in HEAD_TERMS):
            fail(f"{path}: trusted PR workflows must not checkout contributor head code")
    unpinned = [
        reference
        for reference in uses_references(doc)
        if not reference.startswith("./") and not SHA_PIN.search(reference)
    ]
    if unpinned:
        fail(f"{path}: actions must use full commit SHAs: {', '.join(unpinned)}")


def require_text(path: str, text: str | None, needle: str, message: str) -> None:
    if text is None or needle not in text:
        fail(f"{path}: {message}")


def check_publish(path: str, text: str) -> None:
    doc = load_workflow(text, path)
    if doc is None:
        return
    events = triggers(doc)
    if "pull_request" in events:
        fail(f"{path}: privileged workflow must not run on pull requests")
    if "push" not in events:
        fail(f"{path}: trusted push trigger must stay enabled")
    jobs = doc.get("jobs") or {}
    for job in ("publish", "pages", "report-validation-failure", "aislop"):
        if job not in jobs:
            fail(f"{path}: {job} job must stay present")
    aislop = jobs.get("aislop") or {}
    if aislop.get("uses") != "./.github/workflows/aislop.yml":
        fail(f"{path}: main validation must call the Aislop gate")
    publish_if = str((jobs.get("publish") or {}).get("if", ""))
    if "needs.aislop.result == 'success'" not in publish_if:
        fail(f"{path}: publishing must require a successful Aislop gate")
    publish_steps = step_names(doc, "publish")
    if "Trivy critical gate" not in publish_steps:
        fail(f"{path}: Trivy critical gate must stay present")
    require_text(
        path, text, "ignore-unfixed: true", "Trivy gate must ignore unfixed vulnerabilities"
    )
    require_text(
        path,
        text,
        f"{SARIF_CATEGORY}:container",
        "Trivy SARIF must preserve the required analysis configuration",
    )
    require_text(
        path,
        text,
        "bash .github/scripts/upsert-main-failure-issue.sh",
        "failure issues must use the deduplicating reporter",
    )
    require_text(
        path,
        text,
        'echo "published=false" >> "$GITHUB_OUTPUT"',
        "superseded main runs must finish without a false publish failure",
    )
    require_text(
        path,
        text,
        "if: steps.push.outputs.published == 'true'",
        "post-publish supply-chain steps must require a published image",
    )
    require_text(
        path,
        text,
        "actions/deploy-pages@",
        "architecture site must deploy through GitHub Pages Actions",
    )


def check_ci(path: str, text: str) -> None:
    doc = load_workflow(text, path)
    if doc is None:
        return
    if doc.get("name") != "ci":
        fail(f"{path}: workflow name must remain ci")
    jobs = doc.get("jobs") or {}
    if "checks" not in jobs:
        fail(f"{path}: required checks job must stay present")
    if "container" not in jobs:
        fail(f"{path}: required container PR job must stay present")
    elif str(jobs["container"].get("if", "")).strip() != "github.event_name == 'pull_request'":
        fail(f"{path}: container job must stay restricted to pull requests")
    for step in (
        "Gitleaks",
        "Semgrep",
        "Hadolint",
        "Default Compose smoke",
        "Fake Hindsight router-storage parity",
        "Real Hindsight router-storage parity",
        "Trivy PR gate",
    ):
        if step not in step_names(doc, "container") and step not in step_names(doc, "checks"):
            fail(f"{path}: {step} step must stay present")
    require_text(
        path,
        text,
        'npm audit "$@" --audit-level=moderate',
        "Node dependency audit must stay present",
    )
    require_text(
        path,
        text,
        f"{SARIF_CATEGORY}:container",
        "Trivy SARIF must preserve the required default-branch configuration",
    )


def check_aislop(path: str, text: str) -> None:
    doc = load_workflow(text, path)
    if doc is None:
        return
    if doc.get("name") != "aislop":
        fail(f"{path}: workflow name must remain aislop")
    events = triggers(doc)
    if "pull_request" not in events or "workflow_call" not in events:
        fail(f"{path}: pull request and reusable gates must stay enabled")
    if "aislop status" not in {
        str(job.get("name")) for job in (doc.get("jobs") or {}).values() if isinstance(job, dict)
    }:
        fail(f"{path}: required aislop status job must stay present")
    require_text(path, text, "npm run aislop:ci:human", "quality gate must stay present")
    require_text(
        path, text, "npm run --silent aislop:ci:sarif", "main SARIF generation must stay present"
    )
    require_text(
        path, text, "npm run --silent aislop:ci -- --sarif", "PR SARIF generation must stay present"
    )
    require_text(
        path,
        text,
        f"{SARIF_CATEGORY}:status",
        "SARIF must preserve the default-branch configuration",
    )
    require_text(path, text, "Aislop findings gate", "zero-findings gate must stay present")
    require_text(path, text, "process.exit(1)", "findings gate must fail the job")


def check_codeql(path: str, text: str) -> None:
    doc = load_workflow(text, path)
    if doc is None:
        return
    if doc.get("name") != "codeql":
        fail(f"{path}: workflow name must remain codeql")
    if "analyze" not in (doc.get("jobs") or {}):
        fail(f"{path}: required analyze job must stay present")
    require_text(
        path, text, "github/codeql-action/analyze", "CodeQL analyze action must stay present"
    )
    require_text(
        path,
        text,
        f"{SARIF_CATEGORY}:analyze",
        "analysis must preserve the default-branch configuration",
    )


def check_nightly(path: str, text: str) -> None:
    doc = load_workflow(text, path)
    if doc is None:
        return
    if "schedule" not in triggers(doc):
        fail(f"{path}: scheduled trigger must stay enabled")
    for job in ("dependency-audit", "openclaw-compat", "sonar"):
        if job not in (doc.get("jobs") or {}):
            fail(f"{path}: {job} job must stay present")
    require_text(
        path, text, "pip-audit -r requirements.txt", "Python dependency audit must stay present"
    )
    require_text(
        path, text, "check_openclaw_compat.py", "OpenClaw compatibility inventory must stay present"
    )
    require_text(path, text, "SonarQube quality gate", "SonarQube quality gate must stay present")
    require_text(path, text, "sync-sonar-findings.py", "SonarQube finding sync must stay present")


def check_dependabot_workflow(path: str, text: str) -> None:
    doc = load_workflow(text, path)
    if doc is None:
        return
    if "pull_request_target" not in triggers(doc):
        fail(f"{path}: trusted PR trigger must stay enabled")
    require_text(
        path,
        text,
        "ref: ${{ github.workflow_sha }}",
        "automation must load from the trusted workflow revision",
    )
    require_text(
        path,
        text,
        "github.event.pull_request.user.login == 'dependabot[bot]'",
        "PR events must remain restricted to Dependabot",
    )


def check_dependabot_script(path: str, text: str) -> None:
    for needle in ("49699333", "verifiedCommits", "'--auto', '--squash', '--match-head-commit'"):
        require_text(path, text, needle, f"missing safety contract: {needle}")


def check_failure_reporter(path: str, text: str) -> None:
    require_text(
        path, text, "gh issue list --state all", "reporter must search open and closed issues"
    )
    require_text(path, text, "gh issue reopen", "reporter must reopen matching closed issues")
    require_text(
        path, text, "main-failure:${FAILURE_KEY}", "reporter must preserve stable failure keys"
    )


def check_sonar_reporter(path: str, text: str) -> None:
    require_text(
        path,
        text,
        'ISSUE_MARKER_PREFIX = "sonar-finding"',
        "stable finding markers must be preserved",
    )
    if not re.search(r'"gh",\s*"issue",\s*"list",[\s\S]*?"--state",\s*"all"', text):
        fail(f"{path}: reporter must search open and closed issues")
    if not re.search(r'"gh",\s*"issue",\s*"reopen"', text):
        fail(f"{path}: reporter must reopen matching closed issues")
    require_text(path, text, "sinceLeakPeriod=True", "hotspots must stay scoped to new code")


def check_guard(path: str, text: str) -> None:
    require_text(path, text, "policy-guard.py", "guard must run the checked-in policy script")
    require_text(
        path, text, "pull_request.base.sha", "guard script must load from the trusted base revision"
    )


def check_guard_script(path: str, text: str) -> None:
    require_text(path, text, "write-all", "guard must reject write-all permissions")
    require_text(path, text, "SHA_PIN", "guard must enforce SHA-pinned actions")
    require_text(path, text, "pull_request_target", "guard must police trusted PR checkouts")


def check_package_json(path: str, text: str) -> None:
    try:
        scripts = json.loads(text).get("scripts") or {}
    except json.JSONDecodeError:
        fail(f"{path}: package.json must stay valid JSON")
        return
    if scripts.get("aislop:ci") != "aislop ci":
        fail(f"{path}: aislop:ci must remain a full-repository scan")


CONTRACTS: dict[str, Callable[[str, str], None]] = {
    PUBLISH: check_publish,
    CI: check_ci,
    CODEQL: check_codeql,
    AISLOP: check_aislop,
    NIGHTLY: check_nightly,
    DEPENDABOT_WORKFLOW: check_dependabot_workflow,
    GUARD_WORKFLOW: check_guard,
    GUARD_SCRIPT: check_guard_script,
    DEPENDABOT_SCRIPT: check_dependabot_script,
    FAILURE_REPORTER: check_failure_reporter,
    SONAR_REPORTER: check_sonar_reporter,
    PACKAGE_JSON: check_package_json,
}


def main() -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    number = os.environ.get("PR_NUMBER", "")
    head_sha = os.environ.get("HEAD_SHA", "")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository) or not token:
        fail("guard: GITHUB_REPOSITORY and GITHUB_TOKEN are required")
    if not number.isdigit() or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        fail("guard: PR_NUMBER and HEAD_SHA are required")
    if failures:
        print("\n".join(f"- {f}" for f in failures), file=sys.stderr)
        return 1

    github = GitHub(repository, token)
    files = github.pull_files(int(number))
    changed = {
        name for file in files for name in [file["filename"], file.get("previous_filename")] if name
    }
    removed_or_renamed = {
        file["previous_filename"] if file["status"] == "renamed" else file["filename"]
        for file in files
        if file["status"] in ("removed", "renamed")
    }
    workflow_changed = any(
        name.startswith(f"{WORKFLOWS_DIR}/") and name.endswith((".yml", ".yaml"))
        for name in changed
    )
    if not workflow_changed and not changed & (PROTECTED | {PACKAGE_JSON}):
        print("No workflow or policy-sensitive files changed. Policy guard passed.")
        return 0

    for file in files:
        path = file["filename"]
        if file["status"] == "removed":
            continue
        if path.startswith(f"{WORKFLOWS_DIR}/") and path.endswith((".yml", ".yaml")):
            text = github.file_at(path, head_sha)
            if text is not None:
                check_workflow_basics(path, text)

    for path in sorted(changed & (PROTECTED | {PACKAGE_JSON})):
        if path in removed_or_renamed:
            fail(f"{path}: protected file must not be removed or renamed")
            continue
        check = CONTRACTS.get(path)
        if check is None:
            continue
        text = github.file_at(path, head_sha)
        if text is None:
            fail(f"{path}: protected file must not be removed or renamed")
            continue
        check(path, text)

    if failures:
        print("Policy guard failed:", file=sys.stderr)
        print("\n".join(f"- {f}" for f in failures), file=sys.stderr)
        return 1
    print("Policy guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
