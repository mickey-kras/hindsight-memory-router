Warning: truncated output (original token count: 24564)
Total output lines: 1583

"""Exercise release policy against meaningful workflow and source mutations."""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path.cwd()
GUARD = ROOT / ".github/workflows/policy-guard.yml"
ROUTER = (ROOT / ".github/workflows/publish.yml").exists()
MAIN = ".github/workflows/publish.yml" if ROUTER else ".github/workflows/main.yml"
PATHS = [
    ".github/dependency-review-config.yml",
    ".github/workflows/policy-guard.yml",
    MAIN,
    ".github/workflows/release.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/aislop.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/architecture.yml",
    ".github/scripts/report-main-failures.cjs",
    ".github/scripts/report-main-failures.test.cjs",
    ".github/scripts/coverage-artifact.py",
    ".github/scripts/coverage-artifact.test.py",
    ".github/scripts/aislop-cli.test.cjs",
    ".github/scripts/ci-impact.cjs",
    ".github/scripts/ci-impact.test.cjs",
    ".github/workflows/dependency-review.yml",
    ".github/workflows/pr-branch-updater.yml",
    ".github/scripts/pr-branch-updater.cjs",
    ".github/scripts/release.cjs",
    ".github/scripts/release-settings.cjs",
    ".github/rulesets/protect-release-branches.json",
]
if ROUTER:
    PATHS.append(".github/scripts/publish-image.sh")
    PATHS.append(".github/scripts/release-cleanup.cjs")
    PATHS.append(".github/scripts/release-cleanup.test.cjs")
    PATHS.extend([
        ".github/workflows/pr-validation.yml",
        ".github/workflows/docs-ste.yml",
        ".github/scripts/pr-readiness.test.py",
        ".github/scripts/provenance.cjs",
        ".github/scripts/provenance.test.cjs",
        ".github/scripts/attest-image.cjs",
        ".github/scripts/attest-image.test.cjs",
        ".github/scripts/attestation-smoke.sh",
    ])


def policy(overrides=None, paths=None, reviews=None, rules=None, pull=None, base_overrides=None, statuses=None, current_pull=None,
           sources=None, settings_review=""):
    files = {
        str(path.relative_to(ROOT)): path.read_text()
        for path in (ROOT / ".github").rglob("*")
        if path.is_file() and path.suffix in {".yml", ".yaml", ".cjs", ".mjs", ".py", ".sh", ".json"}
    }
    for name in [".aislop/config.yml", ".semgrep.yml", ".gitleaks.toml", ".gitleaksignore"]:
        files[name] = (ROOT / name).read_text()
    files["package.json"] = (ROOT / "package.json").read_text()
    files[".github/CODEOWNERS"] = (ROOT / ".github/CODEOWNERS").read_text()
    base_files = {**files, **(base_overrides or {})}
    files.update(overrides or {})
    guard = yaml.safe_load(GUARD.read_text())
    steps = guard["jobs"]["guard"]["steps"]
    if ROUTER:
        script = next(step["with"]["script"] for step in steps if "script" in step.get("with", {}))
        driver = r"""
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const failures = [];
let pullReads = 0;
const github = { paginate: async method => method === github.rest.pulls.listReviews ? input.reviews :
    typeof method === 'string' ? input.rules :
    input.paths.map(filename => ({filename, status: input.statuses[filename] || 'modified'})),
  request: async () => ({data: input.rules}),
  rest: { pulls: {listFiles() {}, listReviews() {}, get: async () => ({data: pullReads++ ? input.current_pull || input.pull : input.pull})},
    repos: {getRepoRuleset: async ({ruleset_id}) => ({data: input.sources[String(ruleset_id)]}),
      getContent: async ({path, ref}) => ({data: {
      type: 'file', content: Buffer.from((ref === input.pull.base.sha ? input.base_files : input.files)[path]).toString('base64'), encoding: 'base64'
    }})}}};
const context = {repo: {owner: 'test', repo: 'test'}, payload: {pull_request: input.pull}};
const core = {setFailed: text => failures.push(text), info() {}};
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
new AsyncFunction('github', 'context', 'core', 'require', input.script)(github, context, core, require)
  .then(() => process.stdout.write(JSON.stringify(failures))).catch(error => {console.error(error); process.exit(1);});
"""
        result = subprocess.run(
            ["node", "-e", driver],
            env={**os.environ, "POLICY_TOOLS_DIRECTORY": os.environ.get("POLICY_TOOLS_DIRECTORY", str(ROOT / ".github/scripts")),
                 "CI_POLICY_SETTINGS_REVIEW": settings_review},
            input=json.dumps({"script": script, "files": files, "base_files": base_files, "paths": paths if paths is not None else PATHS,
                              "reviews": reviews or [], "rules": rules or [], "statuses": statuses or {}, "current_pull": current_pull,
                              "sources": sources if sources is not None else {"42": {
                                  "id": 42, "source_type": "Repository", "source": "test/test", "enforcement": "active",
                                  "target": "branch", "updated_at": "2026-10-23T00:00:00Z", "bypass_actors": [], "rules": rules or []}},
                              "pull": pull or {"number": 1, "state": "open", "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40, "ref": "main"},
                                               "user": {"login": "mickey-kras", "type": "User"}}}),
            text=True,
            capture_output=True,
            check=True,
        )
        return json.loads(result.stdout)
    source = ""
    for step in steps:
        run = step.get("run", "")
        if "cat <<'POLICY_SOURCE'" in run:
            source += run.split("\n", 2)[2].rsplit("\nPOLICY_SOURCE", 1)[0] + "\n"
    # Exercise the guard's existing fixture mode in its own process, including
    # its real author checks and main entry point. Do not evaluate source in the
    # test runner or disable the repository's dynamic-execution security rule.
    with tempfile.TemporaryDirectory(prefix="release-policy-") as temporary:
        directory = Path(temporary)
        program = directory / "policy_guard.py"
        program.write_text(source)
        fixtures = directory / "fixtures"
        fixtures.mkdir()
        for path, content in files.items():
            target = fixtures / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        for name, value in {
            "head_sha": "a" * 40,
            "author_association": "OWNER",
            "author_login": "test-owner",
        }.items():
            (fixtures / name).write_text(value)
        changed = directory / "files.json"
        changed.write_text(json.dumps([{"filename": path, "status": "modified"} for path in PATHS]))
        result = subprocess.run(
            [sys.executable, str(program)],
            env={**os.environ, "GUARD_FIXTURE_DIR": str(fixtures), "FILES_JSON": str(changed)},
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        return [] if result.returncode == 0 else [result.stdout + result.stderr]


def quality_gate(needs, event="pull_request", candidate_sha="", candidate_ref="", draft="false"):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    script = workflow["jobs"]["checks"]["steps"][0]["with"]["script"]
    driver = r"""
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const failures = [];
const core = {setFailed: message => failures.push(message)};
new Function('core', input.script)(core);
process.stdout.write(JSON.stringify(failures));
"""
    result = subprocess.run(
        ["node", "-e", driver],
        input=json.dumps({"script": script}),
        env={**os.environ, "NEEDS_JSON": json.dumps(needs), "EVENT_NAME": event,
             "CANDIDATE_SHA": candidate_sha, "CANDIDATE_REF": candidate_ref, "PR_DRAFT": draft},
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def successful_quality_needs():
    needs = {name: {"result": "success", "outputs": {}} for name in
             ["changes", "hindsight", "python", "ui", "release", "security", "container", "docs-ste"]}
    needs["changes"]["outputs"] = {name: "true" for name in ["python", "ui", "release"]}
    for name in ["python", "ui", "release"]:
        needs[name]["outputs"] = {"validation": "full"}
    return needs


def workflow_condition(condition, inputs, event="workflow_dispatch", ref="refs/heads/main", needs=None):
    driver = r"""
const { condition, inputs, event, ref, needs } = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const expression = condition.replace(/^\s*\$\{\{/, '').replace(/\}\}\s*$/, '')
  .replace(/needs\.([\w-]+)/g, (_, name) => `needs[${JSON.stringify(name)}]`);
const success = () => Object.values(needs).every(job => job.result === 'success');
const cancelled = () => Object.values(needs).some(job => job.result === 'cancelled');
const failure = () => Object.values(needs).some(job => job.result === 'failure');
const implicitSuccess = /\b(always|success|failure|cancelled)\(/.test(expression) || success();
const result = implicitSuccess && new Function('inputs', 'github', 'needs', 'success', 'failure',
  'cancelled', 'always', `return (${expression});`)(inputs, { event_name: event, ref }, needs,
  success, failure, cancelled, () => true);
process.stdout.write(JSON.stringify(Boolean(result)));
"""
    result = subprocess.run(
        ["node", "-e", driver],
        input=json.dumps({"condition": condition, "inputs": inputs, "event": event, "ref": ref,
                          "needs": needs or {}}),
        text=True, capture_output=True, check=True,
    )
    return json.loads(result.stdout)


class ReleasePolicyTests(unittest.TestCase):
    def test_parallel_quality_jobs_preserve_required_identities_and_hindsight(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        jobs = workflow["jobs"]
        self.assertEqual(workflow["name"], "ci")
        self.assertEqual(set(jobs), {"changes", "hindsight", "python", "ui", "release", "security", "checks", "container", "docs-ste"})
        self.assertEqual(set(jobs["checks"]["needs"]), set(jobs) - {"checks"})
        self.assertEqual(jobs["checks"]["if"], "always()")
        self.assertEqual(jobs["checks"].get("name", "checks"), "checks")
        self.assertEqual(jobs["container"]["name"], "container")
        self.assertEqual(jobs["container"]["if"], "github.event_name == 'pull_request' && (github.event.pull_request.draft != true || inputs.candidate_sha != '' || inputs.candidate_ref != '')")
        self.assertEqual(jobs["docs-ste"]["uses"], "./.github/workflows/docs-ste.yml")
        self.assertEqual(jobs["docs-ste"]["if"], "github.event_name == 'pull_request'")
        self.assertNotIn("needs", jobs["security"])
        self.assertNotIn("needs", jobs["hindsight"])
        for name in ["ui", "release"]:
            self.assertEqual(jobs[name]["needs"], "changes")
        self.assertEqual(jobs["python"]["needs"], ["changes", "hindsight"])
        self.assertEqual(jobs["container"]["needs"], "hindsight")
        for name in ["hindsight", "python", "ui", "release", "security"]:
            self.assertEqual(jobs[name]["if"], "github.event_name != 'pull_request' || github.event.pull_request.draft != true || inputs.candidate_sha != '' || inputs.candidate_ref != ''")
        for job in jobs.values():
            self.assertNotIn("continue-on-error", job)
            for step in job.get("steps", []):
                self.assertNotIn("continue-on-error", step)
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False)
        self.assertFalse(any(step.get("uses", "").startswith("actions/checkout@") for step in jobs["checks"]["steps"]))
        gate = jobs["checks"]["steps"][0]
        self.assertEqual(gate["env"], {"PR_DRAFT": "${{ github.event.pull_request.draft }}", "NEEDS_JSON": "${{ toJSON(needs) }}", "EVENT_NAME": "${{ github.event_name }}",
                                       "CANDIDATE_SHA": "${{ inputs.candidate_sha }}", "CANDIDATE_REF": "${{ inputs.candidate_ref }}"})
        outputs = workflow.get("on", workflow.get(True))["workflow_call"]["outputs"]
        for name, source in [("version", "version"), ("sha", "sha"), ("image", "image")]:
            self.assertEqual(outputs[f"hindsight_{name}"]["value"], f"${{{{ jobs.hindsight.outputs.{source} }}}}")
        resolve = next(step for step in jobs["hindsight"]["steps"] if step.get("id") == "resolve")
        self.assertEqual(resolve["env"], {"RELEASE_CANDIDATE_SHA": "${{ inputs.candidate_sha }}", "RELEASE_CANDIDATE_REF": "${{ inputs.candidate_ref }}"})
        upstream = next(step for step in jobs["python"]["steps"] if step.get("name") == "Checkout current Hindsight OpenClaw sources")
        self.assertEqual(upstream["with"]["ref"], "${{ needs.hindsight.outputs.sha }}")
        self.assertEqual(jobs["container"]["env"]["HINDSIGHT_TEST_IMAGE"], "${{ needs.hindsight.outputs.image }}")

    def test_quality_gate_rejects_failed_cancelled_missing_and_skipped_jobs(self):
        passing = successful_quality_needs()
        names = list(passing)
        self.assertEqual(quality_gate(passing), [])
        for name in names:
            for state in ["failure", "cancelled", "skipped", "neutral", "", None]:
                with self.subTest(job=name, state=state):
                    changed = {**passing, name: {"result": state}}
                    self.assertTrue(quality_gate(changed))
            self.assertTrue(quality_gate({key: value for key, value in passing.items() if key != name}))
            self.assertTrue(quality_gate({**passing, name: {"outputs": {}}}))
        self.assertTrue(quality_gate({**passing, "unreviewed": {"result": "success"}}))
        self.assertTrue(quality_gate({}))

    def test_quality_gate_allows_only_the_known_non_pr_skips_and_reruns(self):
        passing = successful_quality_needs()
        for event in ["push", "workflow_dispatch"]:
            with self.subTest(event=event):
                baseline = {**passing, "container": {"result": "skipped"}, "docs-ste": {"result": "skipped"}}
                self.assertEqual(quality_gate(baseline, event), [])
                self.assertTrue(quality_gate({**baseline, "security": {"result": "skipped"}}, event))
                for name in ["container", "docs-ste"]:
                    for state in ["success", "failure", "cancelled", None]:
                        self.assertTrue(quality_gate({**baseline, name: {"result": state}}, event))
                    self.assertTrue(quality_gate({key: value for key, value in baseline.items() if key != name}, event))
                self.assertTrue(quality_gate({**baseline, "python": {"result": "failure"}}, event))
                # A failed-job rerun may retain successful results from the first attempt.
                self.assertEqual(quality_gate(baseline, event), [])
        self.assertTrue(quality_gate({**passing, "ui": {"result": "cancelled"}}))
        self.assertEqual(quality_gate(passing), [])

    def test_noops_require_successful_jobs_and_matching_explicit_completion(self):
        passing = successful_quality_needs()
        for name in ["python", "ui", "release"]:
            passing["changes"]["outputs"][name] = "false"
            passing[name]["outputs"]["validation"] = "noop"
        self.assertEqual(quality_gate(passing), [])
        for name in ["python", "ui", "release"]:
            for state in ["failure", "cancelled", "skipped"]:
                self.assertTrue(quality_gate({**passing, name: {"result": state, "outputs": {"validation": "noop"}}}))
            for output in [{}, {"validation": "full"}, {"validation": "skipped"}]:
                self.assertTrue(quality_gate({**passing, name: {"result": "success", "outputs": output}}))
            affected = successful_quality_needs()
            affected[name]["outputs"]["validation"] = "noop"
            self.assertTrue(quality_gate(affected), "Affected work cannot report a successful no-op")
            for value in ["", "False", None]:
                affected["changes"]["outputs"][name] = value
                self.assertTrue(quality_gate(affected))
        for event in ["push", "workflow_dispatch"]:
            self.assertTrue(quality_gate({**passing, "container": {"result": "skipped"}}, event))
        self.assertTrue(quality_gate(passing, candidate_sha="a" * 40))
        self.assertTrue(quality_gate(passing, candidate_ref="refs/heads/release/1"))

    def test_noop_steps_and_full_worker_steps_are_complementary(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        for name in ["python", "ui", "release"]:
            job = jobs[name]
            self.assertEqual(job["if"], "github.event_name != 'pull_request' || github.event.pull_request.draft != true || inputs.candidate_sha != '' || inputs.candidate_ref != ''")
            expected_outputs = {"validation": "${{ steps.completed.outputs.validation }}"}
            if name == "python":
                expected_outputs.update({
                    "coverage_artifact_id": "${{ steps.coverage-upload.outputs.artifact-id }}",
                    "coverage_run_attempt": "${{ steps.coverage-evidence.outputs.run_attempt }}",
                })
            self.assertEqual(job["outputs"], expected_outputs)
            noop, *work, complete = job["steps"]
            self.assertEqual(noop["name"], "Explicit successful no-op")
            self.assertEqual(noop["if"], f"needs.changes.outputs.{name} == 'false'")
            self.assertEqual(complete["id"], "completed")
            self.assertNotIn("if", complete, "Completion must retain default success(), never always()")
            for step in work:
                self.assertIn(f"needs.changes.outputs.{name} != 'false'", step["if"])
            # Run the actual no-op and completion shell, including missing-output
            # fallback. GitHub's normal success() prevents completion after any
            # failed work step; the aggregator separately rejects failed jobs.
            for affected, expected in [("false", "noop"), ("true", "full"), ("", "full")]:
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "output"
                    env = {**os.environ, "AFFECTED": affected, "GITHUB_OUTPUT": str(output)}
                    if affected == "false":
                        result = subprocess.run(["bash", "-eo", "pipefail", "-c", noop["run"]], env=env, capture_output=True, check=True)
                        self.assertIn(b"unaffected", result.stdout)
                    subprocess.run(["bash", "-eo", "pipefail", "-c", complete["run"]], env=env, check=True)
                    self.assertEqual(output.read_text(), f"validation={expected}\n")
        for name in ["security", "container", "hindsight"]:
            for step in jobs[name]["steps"]:
                self.assertNotIn("needs.changes", step.get("if", ""))
        checkout = jobs["changes"]["steps"][0]
        self.assertEqual(checkout["with"]["fetch-depth"], 0)

    def test_classifier_and_noop_bypasses_fail_reviewed_policy(self):
        path = ".github/workflows/ci.yml"
        original = (ROOT / path).read_text()
        for before, after in [
            ("`${baseSha}:.github/scripts/ci-impact.cjs`", "`${headSha}:.github/scripts/ci-impact.cjs`"),
            ("&& !process.env.CANDIDATE_REF", ""),
            ("typeof result[name] !== 'boolean'", "false"),
            ("if: needs.changes.outputs.python == 'false'", "if: false"),
            ("id: completed\n", "id: completed\n        if: always()\n"),
            ("needs[name]?.outputs?.validation !== expected", "false"),
        ]:
            changed = original.replace(before, after)
            self.assertNotEqual(changed, original)
            self.assertTrue(policy({path: changed}))
        for path in [".github/scripts/ci-impact.cjs", ".github/scripts/ci-impact.test.cjs"]:
            self.assertTrue(policy({path: (ROOT / path).read_text() + "\n// unreviewed change\n"}))

    def test_quality_worker_gates_and_diagnostics_remain_local(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        required = {
            "python": ["Python runtime lock is current", "Python dev lock is current", "No legacy TypeScript runtime or tests", "OpenClaw compatibility inventory", "Unicode confusables map is reproducible", "Tests and coverage"],
            "ui": ["Aislop CLI regression tests", "UI unit, crypto, and build checks", "UI package consumer check", "Install Playwright Chromium", "UI browser tests", "OpenAPI contract", "Upload OpenAPI diagnostics"],
            "release": ["npm audit filter tests", "Release automation tests", "Attestation CLI and registry compatibility", "Release policy tests", "PR branch updater tests", "Failure reporter tests"],
            "security": [ "Python dependency audit", "Bandit", "Node tooling audit", "Gitleaks", "Upload redacted secret scan", "Semgrep", "Hadolint"],
            "container": ["Default Compose smoke", "Fake Hindsight router-storage parity", "Real Hindsight router-storage parity", "Trivy PR gate"],
        }
        for name, gates in required.items():
            steps = {step.get("name"): step for step in jobs[name]["steps"]}
            for gate in gates:
                self.assertIn(gate, steps)
        coverage = next(step for step in jobs["python"]["steps"] if step.get("name") == "Tests and coverage")
        self.assertEqual(coverage["run"], "python -m pytest -n 2 --cov --cov-config=pyproject.toml --cov-report=term-missing --cov-fail-under=90 --durations=30")
        ui_steps = jobs["ui"]["steps"]
        npm_install = next(index for index, step in enumerate(ui_steps) if step.get("run") == "npm ci")
        aislop_test = next(index for index, step in enumerate(ui_steps) if step.get("name") == "Aislop CLI regression tests")
        self.assertLess(npm_install, aislop_test)
        self.assertEqual(ui_steps[aislop_test]["run"], "node --test .github/scripts/aislop-cli.test.cjs")
        self.assertEqual(ui_steps[aislop_test]["if"], "${{ needs.changes.outputs.ui != 'false' }}")
        runtime_install = next(index for index, step in enumerate(ui_steps) if step.get("run") == "python -m pip install --require-hashes -r requirements.txt")
        ui_test = next(index for index, step in enumerate(ui_steps) if step.get("name") == "UI unit, crypto, and build checks")
        self.assertLess(runtime_install, ui_test)
        self.assertTrue(any(step.get("uses", "").startswith("actions/setup-python@") for step in ui_steps[:runtime_install]))
        for job in jobs.values():
            steps = {step.get("name"): step for step in job.get("steps", [])}
            step_ids = {step["id"] for step in job.get("steps", []) if "id" in step}
            for name, step in steps.items():
                if name and name.startswith("Upload"):
                    for source in re.findall(r"steps\.([\w-]+)\.outcome", step.get("if", "")):
                        self.assertIn(source, step_ids)
                    if step.get("uses", "").startswith("actions/upload-artifact@"):
                        self.assertEqual(step["with"]["if-no-files-found"], "error")

    def test_parallel_quality_bypasses_fail_reviewed_policy(self):
        path = ".github/workflows/ci.yml"
        original = (ROOT / path).read_text()
        mutations = [
            original.replace("    if: always()", "    if: success()"),
            original.replace("needs: [changes, hindsight, python, ui, release, security, container, docs-ste]", "needs: [changes, hindsight, python, ui, release, security, container]"),
            original.replace("result !== expected", "false"),
            original.replace("  security:\n", "  security:\n    continue-on-error: true\n"),
            original.replace("  ui:\n", "  ui:\n    if: false\n"),
            original.replace("--cov-fail-under=90", "--cov-fail-under=0"),
            original.replace("ref: ${{ inputs.candidate_sha }}", "ref: main"),
            original.replace("github.run_attempt", "github.run_id"),
        ]
        for changed in mutations:
            with self.subTest(mutation=changed):
                self.assertNotEqual(changed, original)
                self.assertTrue(policy({path: changed}))

    @staticmethod
    def aislop_report(findings=None):
        return {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "aislop", "version": "0.18.1", "rules": []}},
                "results": findings or [],
            }],
        }

    @staticmethod
    def aislop_finding(rule="test/finding", level="warning"):
        return {
            "ruleId": rule,
            "level": level,
            "message": {"text": "Finding details"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/example.js"},
                "region": {"startLine": 7},
            }}],
        }

    def run_aislop_steps(self, report, exit_code=0):
        workflow = yaml.safe_load((ROOT / ".github/workflows/aislop.yml").read_text())
        steps = {step.get("name"): step for step in workflow["jobs"]["status"]["steps"]}
        with tempfile.TemporaryDirectory(prefix="aislop-workflow-") as temporary:
            directory = Path(temporary)
            scanner = directory / "trusted/.github/trusted-ci/aislop.mjs"
            scanner.parent.mkdir(parents=True)
            scanner.write_text("""
import fs from 'node:fs';
fs.appendFileSync('invocations.jsonl', JSON.stringify(process.argv.slice(2)) + '\\n');
if (process.env.AISLOP_TEST_MISSING === 'true') fs.rmSync('aislop.sarif', {force: true});
else process.stdout.write(process.env.AISLOP_TEST_REPORT);
process.stderr.write('scanner diagnostic\\n');
process.exit(Number(process.env.AISLOP_TEST_EXIT));
""")
            env = {
                **os.environ,
                "PATH": f"{directory}{os.pathsep}{os.environ['PATH']}",
                "RUNNER_TEMP": str(directory),
                "AISLOP_TEST_REPORT": report if isinstance(report, str) else json.dumps(report),
                "AISLOP_TEST_MISSING": str(report is None).lower(),
                "AISLOP_TEST_EXIT": str(exit_code),
            }

            def run_step(name):
                return subprocess.run(  # noqa: S603
                    ["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", steps[name]["run"]],
                    cwd=directory, env=env, text=True, capture_output=True, timeout=10,
                    check=False,
                )
            scan = run_step("Aislop quality gate")
            findings = run_step("Aislop findings gate")
            invocations = [json.loads(line) for line in (directory / "invocations.jsonl").read_text().splitlines()]
            self.assertEqual(invocations, [[str(directory / "scan"), "sarif"]])
            self.assertIn("scanner diagnostic", scan.stderr)
            if report is not None:
                expected = report if isinstance(report, str) else json.dumps(report)
                self.assertEqual((directory / "aislop.sarif").read_text(), expected)
            return scan, findings

    def test_aislop_single_scan_contract(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/aislop.yml").read_text())
        steps = workflow["jobs"]["status"]["steps"]
        scans = [step for step in steps if "aislop.mjs" in step.get("run", "")]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["name"], "Aislop quality gate")
        self.assertNotIn("if", scans[0])
        self.assertFalse(scans[0].get("continue-on-error", False))
        named = {step.get("name"): step for step in steps}
        self.assertEqual(named["Aislop findings gate"]["if"], "always()")
        self.assertFalse(named["Aislop findings gate"].get("continue-on-error", False))
        upload = named["Upload Aislop SARIF"]
        self.assertIn("always()", upload["if"])
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", upload["if"])
        self.assertEqual(upload["with"], {
            "checkout_path": "${{ runner.temp }}/scan",
            "sarif_file": "aislop.sarif",
            "category": ".github/workflows/publish.yml:status",
            "ref": "${{ inputs.candidate_ref }}",
            "sha": "${{ inputs.candidate_sha }}",
        })
        config = yaml.safe_load((ROOT / ".aislop/config.yml").read_text())
        self.assertEqual(config["ci"]["failBelow"], 100)

    def test_aislop_callers_and_checkout_keep_candidate_attribution(self):
        path = ".github/workflows/aislop.yml"
        workflow = yaml.safe_load((ROOT / path).read_text())
        inputs = workflow.get("on", workflow.get(True))["workflow_call"]["inputs"]
        self.assertEqual(inputs, {
            "candidate_sha": {"type": "string", "default": ""},
            "candidate_ref": {"type": "string", "default": ""},
        })
        checkout = next(step for step in workflow["jobs"]["status"]["steps"] if step.get("name") == "Check out candidate source")
        self.assertEqual(checkout["with"]["ref"], "${{ inputs.candidate_sha }}")
        self.assertEqual(checkout["with"]["fetch-depth"], 0)
        pr = yaml.safe_load((ROOT / ".github/workflows/pr-validation.yml").read_text())["jobs"]["aislop"]
        self.assertEqual(pr["uses"], f"./{path}")
        self.assertNotIn("with", pr)
        candidate = yaml.safe_load((ROOT / MAIN).read_text())["jobs"]["aislop"]
        self.assertEqual(candidate["uses"], f"./{path}")
        self.assertEqual(candidate["with"], {
            "candidate_sha": "${{ inputs.candidate_sha }}",
            "candidate_ref": "${{ inputs.candidate_ref }}",
        })

    def test_aislop_clean_report_uses_one_scan(self):
        scan, findings = self.run_aislop_steps(self.aislop_report())
        self.assertEqual((scan.returncode, findings.returncode), (0, 0))
        self.assertIn("Aislop SARIF: 0 finding(s).", findings.stdout)

    def test_aislop_score_and_scanner_failures_keep_their_exit_status(self):
        for exit_code in [1, 2, 127]:
            with self.subTest(exit_code=exit_code):
                scan, findings = self.run_aislop_steps(self.aislop_report(), exit_code)
                self.assertEqual(scan.returncode, exit_code)
                self.assertEqual(findings.returncode, 0)

    def test_aislop_findings_fail_even_when_scanner_score_passes(self):
        for level in ["error", "warning", "note"]:
            with self.subTest(level=level):
                scan, findings = self.run_aislop_steps(self.aislop_report([self.aislop_finding(level=level)]))
                self.assertEqual((scan.returncode, findings.returncode), (0, 1))
                self.assertIn('"src/example.js":7', findings.stdout)
                self.assertIn("Finding details", findings.stdout)
                self.assertIn("Aislop reported 1 finding(s): test/finding", findings.stderr)

    def test_aislop_audit_exception_matches_only_its_exact_rule(self):
        skipped = self.aislop_finding("security/dependency-audit-skipped")
        scan, findings = self.run_aislop_steps(self.aislop_report([skipped]))
        self.assertEqual((scan.returncode, findings.returncode), (0, 0))
        self.assertIn("required CI audit remains authoritative", findings.stderr)
        scan, findings = self.run_aislop_steps(self.aislop_report([skipped]), exit_code=1)
        self.assertEqual((scan.returncode, findings.returncode), (1, 0))
        for rule in ["security/dependency-audit-skipped-extra", "security/vulnerable-dependency"]:
            with self.subTest(rule=rule):
                scan, findings = self.run_aislop_steps(self.aislop_report([skipped, self.aislop_finding(rule)]))
                self.assertEqual((scan.returncode, findings.returncode), (0, 1))
                self.assertIn(f"Aislop reported 1 finding(s): {rule}", findings.stderr)

    def test_aislop_summary_uses_all_runs_and_keeps_report_text_on_one_line(self):
        report = self.aislop_report([self.aislop_finding("security/dependency-audit-skipped")])
        finding = self.aislop_finding()
        finding["message"]["text"] = "First line\n::error::embedded report text"
        report["runs"].extend(self.aislop_report([finding])["runs"])
        scan, findings = self.run_aislop_steps(report)
        self.assertEqual((scan.returncode, findings.returncode), (0, 1))
        self.assertIn("Aislop SARIF: 2 finding(s).", findings.stdout)
        self.assertIn("First line\\n::error::embedded report text", findings.stdout)
        self.assertNotIn("\n::error::", findings.stdout)

    def test_aislop_malformed_empty_and_missing_reports_fail_closed(self):
        invalid_run = self.aislop_report()
        del invalid_run["runs"][0]["results"]
        invalid_finding = self.aislop_report([{"ruleId": "security/dependency-audit-skipped"}])
        for report in [None, "", "{", "null", {}, {"version": "2.1.0", "runs": []}, invalid_run, invalid_finding]:
            with self.subTest(report=report):
                scan, findings = self.run_aislop_steps(report)
                self.assertEqual(scan.returncode, 0)
                self.assertNotEqual(findings.returncode, 0)
                self.assertNotIn("Aislop SARIF:", findings.stdout)
        scan, findings = self.run_aislop_steps("", exit_code=2)
        self.assertEqual(scan.returncode, 2)
        self.assertNotEqual(findings.returncode, 0)

    def test_aislop_quality_command_bypasses_fail_semantic_policy(self):
        path = ".github/workflows/aislop.yml"
        original = (ROOT / path).read_text()
        for command in ['aislop.mjs "$RUNNER_TEMP/scan" human', 'aislop.mjs "$RUNNER_TEMP/scan" sarif || true', 'aislop.mjs "$RUNNER_TEMP/scan" sarif --changes']:
            with self.subTest(command=command):
                changed = original.replace('aislop.mjs "$RUNNER_TEMP/scan" sarif', command)
                self.assertIn(
                    "aislop.yml: one full-repository SARIF scan must preserve the CLI quality exit status",
                    "\n".join(policy({path: changed})),
                )

    def test_aislop_cli_regression_gate_and_test_are_protected(self):
        path = ".github/workflows/ci.yml"
        original = (ROOT / path).read_text()
        changed = original.replace("node --test .github/scripts/aislop-cli.test.cjs", "true")
        self.assertIn("ci.yml: pinned Aislop CLI regression tests must stay present", "\n".join(policy({path: changed})))
        path = ".github/scripts/aislop-cli.test.cjs"
        original = (ROOT / path).read_text()
        self.assertIn(
            f"{path}: release automation must match its reviewed policy",
            "\n".join(policy({path: original + "\n// Mutated regression coverage.\n"})),
        )

    def test_workflow_release_contract(self):
        main = yaml.safe_load((ROOT / MAIN).read_text())
        events = main.get("on", main.get(True))
        self.assertEqual(events["push"], {"branches": ["main"]})
        self.assertIn("workflow_dispatch", events)
        self.assertIsNone(events["workflow_dispatch"])
        self.assertNotIn("prepare-release", main["jobs"])
        release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        self.assertEqual(release.get("on", release.get(True)), {"workflow_dispatch": None})
        baseline = release["jobs"]["baseline"]
        self.assertEqual(baseline["uses"], "./.github/workflows/publish.yml")
        self.assertEqual(baseline["needs"], "entry")
        self.assertEqual(baseline["with"], {"validation_only": True})
        entry = release["jobs"]["entry"]
        self.assertEqual(entry["permissions"], {})
        self.assertNotIn("environment", entry)
        self.assertNotIn("secrets", entry)
        script = entry["steps"][0]["with"]["script"]
        self.assertIn("context.ref !== 'refs/heads/main'", script)
        self.assertIn("throw new Error", script)
        self.assertNotIn("actions/checkout", str(entry))
        prepare = release["jobs"]["prepare-release"]
        self.assertEqual(prepare["needs"], "baseline")
        self.assertEqual(prepare["environment"], "release-automation")
        candidate = release["jobs"]["release"]
        self.assertEqual(candidate["needs"], "prepare-release")
        self.assertEqual(candidate["uses"], baseline["uses"])
        for caller in [baseline, candidate]:
            self.assertEqual(caller["permissions"]["actions"], "read")
        self.assertEqual(candidate["with"], {
            "candidate_sha": "${{ needs.prepare-release.outputs.sha }}",
            "candidate_ref": "${{ needs.prepare-release.outputs.ref }}",
        })
        publish = main["jobs"]["publish"]
        self.assertTrue({"quality", "aislop", "codeql", "architecture"} <= set(publish["needs"]))
        self.assertNotIn("sonar", publish["needs"])
        steps = {step.get("name"): step for step in publish["steps"]}
        for name in ["Log in to GHCR", "Log in to Docker Hub", "Push the scanned image", "Release App token"]:
            self.assertEqual(steps[name]["if"], "inputs.candidate_sha != ''")
        for name in ["sonar", "pages", "update-pr-branches"]:
            self.assertIn("inputs.candidate_sha == ''", main["jobs"][name]["if"])
        sonar_steps = {step.get("name"): step for step in main["jobs"]["sonar"]["steps"]}
        self.assertIn("SonarQube quality gate", sonar_steps)
        self.assertNotIn("SonarQube analysis", steps)
        self.assertEqual(steps["Publish immutable release"]["if"], "steps.push.outputs.published == 'true'")
        self.assertEqual(steps["Promote latest released image"]["if"], "steps.finalized.outputs.latest == 'true'")
        for name in ["Default Compose smoke", "Fake Hindsight router-storage parity", "Real Hindsight router-storage parity"]:
            self.assertIn(name, steps)
        self.assertIn("--exit-code 1", steps["Trivy critical gate"]["run"])
        self.assertEqual(publish["env"]["HINDSIGHT_TEST_IMAGE"], "${{ needs.quality.outputs.hindsight_image }}")

    def test_validation_only_baseline_preserves_validation_and_limits_side_effects(self):
        main = yaml.safe_load((ROOT / MAIN).read_text())
        architecture = yaml.safe_load((ROOT / ".github/workflows/architecture.yml").read_text())
        for workflow in [main, architecture]:
            inputs = workflow.get("on", workflow.get(True))["workflow_call"]["inputs"]
            self.assertEqual(inputs["validation_only"]["type"], "boolean")
            self.assertIs(inputs["validation_only"]["default"], False)
        jobs = main["jobs"]
        self.assertEqual(jobs["architecture"]["with"]["validation_only"], "${{ inputs.validation_only == true }}")
        architecture_steps = architecture["jobs"]["validate"]["steps"]
        pages_steps = [step for step in architecture_steps if step.get("name") in
                       ["Name architecture Pages artifact", "Upload architecture Pages artifact"]]
        self.assertEqual(len(pages_steps), 2)
        for step in architecture_steps:
            if step not in pages_steps:
                self.assertNotIn("validation_only", json.dumps(step))
        for name, job in jobs.items():
            if name not in ["pages", "update-pr-branches", "architecture"]:
                self.assertNotIn("validation_only", json.dumps(job))
        for event, ref, candidate, mode, validation, publication in [
            ("push", "refs/heads/main", "", False, True, True),
            ("push", "refs/heads/main", "", None, True, True),
            ("workflow_dispatch", "refs/heads/main", "", False, True, True),
            ("workflow_dispatch", "refs/heads/main", "", True, True, False),
            ("workflow_dispatch", "refs/heads/main", "b" * 40, False, True, False),
            ("workflow_dispatch", "refs/heads/main", "b" * 40, True, True, False),
            ("pull_request", "refs/pull/1/merge", "", False, False, False),
            ("workflow_dispatch", "refs/heads/topic", "", True, False, False),
        ]:
            inputs = {"candidate_sha": candidate, "candidate_ref": "refs/heads/release/0.1.0" if candidate else "",
                      "validation_only": mode}
            if mode is None:
                del inputs["validation_only"]
            with self.subTest(event=event, ref=ref, candidate=bool(candidate), mode=mode):
                self.assertEqual(workflow_condition(jobs["architecture"]["with"]["validation_only"], inputs),
                                 mode is True)
                for name in ["quality", "aislop", "codeql", "architecture", "publish"]:
                    needs = {key: {"result": "success"} for key in jobs[name].get("needs", [])}
                    self.assertEqual(workflow_condition(jobs[name]["if"], inputs, event, ref, needs), validation)
                self.assertEqual(workflow_condition(jobs["sonar"]["if"], inputs, event, ref),
                                 validation and not candidate)
                for condition in [jobs["pages"]["if"], jobs["update-pr-branches"]["if"],
                                  *(step["if"] for step in pages_steps)]:
                    self.assertEqual(workflow_condition(condition, inputs, event, ref), publication)

    def test_baseline_failures_block_preparation_and_remain_reportable(self):
        release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]
        prepare = release["prepare-release"]
        self.assertEqual(prepare["needs"], "baseline")
        self.assertNotIn("continue-on-error", release["baseline"])
        self.assertNotIn("if", prepare)
        main = yaml.safe_load((ROOT / MAIN).read_text())["jobs"]
        reporter = main["report-validation-failure"]
        inputs = {"candidate_sha": "", "candidate_ref": "", "validation_only": True}
        passing = {name: {"result": "success"} for name in reporter["needs"]}
        for side_effect in ["pages", "update-pr-branches"]:
            passing[side_effect] = {"result": "skipped"}
        self.assertFalse(workflow_condition(reporter["if"], inputs, needs=passing))
        for name in ["quality", "aislop", "codeql", "architecture", "publish", "sonar"]:
            with self.subTest(failed=name):
                failed = {**passing, name: {"result": "failure"}}
                self.assertTrue(workflow_condition(reporter["if"], inputs, needs=failed))
        for state in ["failure", "cancelled", "skipped"]:
            self.assertFalse(workflow_condition(prepare.get("if", "success()"), inputs,
                                               needs={"baseline": {"result": state}}))

    def test_validation_only_gate_and_side_effect_regressions_fail_policy(self):
        release_path = ".github/workflows/release.yml"
        release = (ROOT / release_path).read_text()
        main = (ROOT / MAIN).read_text()
        sonar_condition = yaml.safe_load(main)["jobs"]["sonar"]["if"]
        architecture_path = ".github/workflows/architecture.yml"
        architecture = (ROOT / architecture_path).read_text()
        mutations = [
            (release_path, release.replace("validation_only: true", "validation_only: false")),
            (release_path, release.replace("needs: baseline", "needs: entry")),
            (MAIN, main.replace(" && !inputs.validation_only", "")),
            (MAIN, main.replace(f"    if: {sonar_condition}\n",
                                f"    if: {sonar_condition} && !inputs.validation_only\n")),
            (MAIN, main.replace("      - name: Trivy critical gate", "      - if: false\n        name: Trivy critical gate")),
            (architecture_path, architecture.replace(" && !inputs.validation_only", "")),
        ]
        for path, changed in mutations:
            with self.subTest(path=path, changed=changed[:30]):
                self.assertNotEqual(changed, (ROOT / path).read_text())
                self.assertTrue(policy({path: changed}))

    def test_dependency_review_contract(self):
        validation = yaml.safe_load((ROOT / ".github/workflows/pr-validation.yml").read_text())
        self.assertEqual(
            validation["jobs"]["dependency-review"]["uses"],
            "./.github/workflows/dependency-review.yml",
        )
        workflow = yaml.safe_load((ROOT / ".github/workflows/dependency-review.yml").read_text())
        events = workflow.get("on", workflow.get(True))
        self.assertEqual(set(events), {"workflow_call"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        review = next(
            step
            for job in workflow["jobs"].values()
            for step in job.get("steps", [])
            if step.get("uses", "").startswith("actions/dependency-review-action@")
        )
        self.assertRegex(review["uses"], r"@[0-9a-f]{40}$")
        config_path = ROOT / review["with"]["config-file"].removeprefix("./")
        config = yaml.safe_load(config_path.read_text())
        self.assertEqual(config["fail-on-severity"], "high")
        self.assertTrue(config["vulnerability-check"])
        self.assertFalse(config["license-check"])
        self.assertFalse(config["warn-only"])
        self.assertEqual(set(config["fail-on-scopes"]), {"runtime", "development", "unknown"})

    def test_dependency_vulnerability_bypasses_fail_policy(self):
        path = ".github/dependency-review-config.yml"
        original = (ROOT / path).read_text()
        for changed in [
            original.replace("vulnerability-check: true", "vulnerability-check: false"),
            original.replace("warn-only: false", "warn-only: true"),
            original.replace("high", "critical"),
            original.replace("  - development\n", ""),
            original + "allow-ghsas: [GHSA-xxxx-xxxx-xxxx]\n",
        ]:
            self.assertTrue(policy({path: changed}))


    def test_release_sbom_contract(self):
        if not ROUTER:
            self.skipTest("router publish workflow required")
        publish = yaml.safe_load((ROOT / MAIN).read_text())["jobs"]["publish"]
        steps = {step.get("name"): step for step in publish["steps"]}
        gate = "steps.push.outputs.published == 'true'"
        for name in ["Generate CycloneDX SBOM", "Attest GHCR SBOM", "Attest Docker Hub SBOM"]:
            expected = gate + " && steps.candidate.outputs.release_assets == ''" if name == "Generate CycloneDX SBOM" else gate
            self.assertEqual(steps[name]["if"], expected)
        generate = steps["Generate CycloneDX SBOM"]["run"]
        self.assertIn("--format cyclonedx", generate)
        self.assertIn("normalize-sbom.py", generate)
        self.assertIn("@${GHCR_DIGEST}", generate)
        for name, registry in [("Attest GHCR SBOM", "IMAGE_GHCR"), ("Attest Docker Hub SBOM", "IMAGE_DOCKERHUB")]:
            step = steps[name]
            self.assertRegex(step["uses"], r"^actions/github-script@[0-9a-f]{40}$")
            self.assertEqual(step["env"]["ATTEST_PREDICATE"], "sbom.cdx.json")
            self.assertEqual(step["env"]["ATTEST_TYPE"], "https://cyclonedx.org/bom")
            self.assertEqual(step["env"]["ATTEST_IMAGE"], f"${{{{ env.{registry} }}}}")
            self.assertIn("attestImage", step["with"]["script"])
        self.assertIn("sbom=sha256:", steps["Record image digests"]["run"])
        script = (ROOT / ".github/scripts/release.cjs").read_text()
        self.assertIn('"sbom.cdx.json"', script)

    def test_attestations_remove_the_affected_dependency_and_retain_verified_bundles(self):
        if not ROUTER:
            self.skipTest("router publish workflow required")
        manifest = json.loads((ROOT / ".github/scripts/package.json").read_text())
        lock = json.loads((ROOT / ".github/scripts/package-lock.json").…564 tokens truncated…= publish["steps"]
        names = [step.get("name") for step in steps]
        ordered = ["Sign the UI package", "Upload image digests", "Publish immutable release",
                   "Verify signed UI package", "Publish verified UI tarball to public npm",
                   "Promote latest released image"]
        self.assertEqual(sorted(names.index(name) for name in ordered),
                         [names.index(name) for name in ordered])
        npm = next(step for step in steps if step.get("name") == ordered[-2])
        self.assertEqual(npm["if"], "steps.push.outputs.published == 'true'")
        self.assertIn("node .github/scripts/publish-npm.cjs", npm["run"])
        self.assertNotIn("npm pack", npm["run"])
        self.assertEqual(publish["permissions"]["id-token"], "write")
        self.assertEqual(publish["environment"], "release-automation")
        self.assertNotIn("NODE_AUTH_TOKEN", json.dumps(publish))
        self.assertIs(json.loads((ROOT / "package.json").read_text())["private"], True)

    def test_release_cleanup_contract(self):
        main = yaml.safe_load((ROOT / MAIN).read_text())
        publish = main["jobs"]["publish"]
        self.assertEqual(publish["outputs"]["released"], "${{ steps.finalized.outputs.latest }}")
        self.assertEqual(publish["outputs"]["ghcr_digest"], "${{ steps.push.outputs.ghcr_digest }}")
        cleanup = main["jobs"]["cleanup"]
        self.assertEqual(set(cleanup["needs"]), {"quality", "aislop", "codeql", "architecture", "publish"})
        self.assertIs(cleanup["continue-on-error"], True)
        condition = cleanup["if"]
        for guard in ["!cancelled()", "inputs.candidate_sha != ''", "needs.publish.outputs.released == ''"]:
            self.assertIn(guard, condition)
        for need in cleanup["needs"]:
            self.assertIn(f"needs.{need}.result == 'failure'", condition)
        self.assertNotIn("always()", condition)
        self.assertEqual(cleanup["environment"], "release-automation")
        self.assertEqual(cleanup["permissions"], {"contents": "read", "packages": "write"})
        steps = {step.get("name"): step for step in cleanup["steps"]}
        self.assertNotIn("Release App token", steps)
        for name in ["Remove orphaned registry tags", "Retain the failed release branch"]:
            self.assertIn("target:", steps[name]["with"]["script"])
            self.assertNotIn("github-token", steps[name]["with"])
        root = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        retained = root["jobs"]["retain-preparation"]
        self.assertIn("!cancelled()", retained["if"])
        self.assertIn("needs.prepare-release.result == 'failure'", retained["if"])
        self.assertEqual(retained["permissions"], {"contents": "read"})

    def test_recovery_reuses_prepared_assets_and_retries_with_the_job_token(self):
        if not ROUTER:
            self.skipTest("router publish workflow required")
        main = yaml.safe_load((ROOT / MAIN).read_text())
        root = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        prepare = root["jobs"]["prepare-release"]
        self.assertEqual(prepare["permissions"], {"contents": "read", "actions": "write"})
        steps = {step.get("name"): step for step in prepare["steps"]}
        resume = steps["Resume the prepared release"]
        self.assertNotIn("github-token", resume["with"])
        self.assertIn("resume_sha", resume["if"])
        self.assertNotIn("permission-actions", steps["Release App token"]["with"])
        publish = {step.get("name"): step for step in main["jobs"]["publish"]["steps"]}
        self.assertIn("retryArtifacts", publish["Find previously tested image"]["with"]["script"])
        self.assertIn("release_assets != ''", publish["Restore prepared release assets"]["if"])
        self.assertIn("restoreReleaseAssets", publish["Verify and restore release bytes"]["with"]["script"])
        for name in ["Generate CycloneDX SBOM", "Sign the UI package", "Record image digests", "Upload image digests"]:
            self.assertIn("release_assets == ''", publish[name]["if"])
        self.assertIn('if [ -z "$RELEASE_ASSETS" ]', publish["Build and pack the UI package"]["run"])

    def test_release_followup_contract(self):
        if not ROUTER:
            self.skipTest("router publish workflow required")
        main = yaml.safe_load((ROOT / MAIN).read_text())
        followup = main["jobs"]["release-followup"]
        self.assertEqual(followup["needs"], ["publish"])
        self.assertNotIn("continue-on-error", followup)
        self.assertEqual(followup["environment"], "release-automation")
        self.assertEqual(followup["permissions"], {"contents": "read"})
        condition = followup["if"]
        for guard in [
            "inputs.candidate_sha != ''",
            "needs.publish.result == 'success'",
            "needs.publish.outputs.released != ''",
        ]:
            self.assertIn(guard, condition)
        self.assertNotIn("cancelled", condition)
        steps = {step.get("name"): step for step in followup["steps"]}
        token = steps["Release App token"]["with"]
        self.assertEqual(token["private-key"], "${{ secrets.RELEASE_APP_PRIVATE_KEY }}")
        self.assertEqual(token["permission-contents"], "write")
        self.assertEqual(token["permission-pull-requests"], "write")
        bump = steps["Open the next version bump pull request"]
        self.assertEqual(bump["with"]["github-token"], "${{ steps.app.outputs.token }}")
        self.assertIn("release.cjs').bumpReleasedVersion(", bump["with"]["script"])
        self.assertEqual(bump["env"]["GH_TOKEN"], "${{ steps.app.outputs.token }}")
        delete = steps["Delete the published release branch"]
        self.assertEqual(delete["if"], "success()")
        self.assertEqual(delete["with"]["github-token"], "${{ steps.app.outputs.token }}")
        self.assertIn("release.cjs').deletePublishedBranch(", delete["with"]["script"])

    def test_failure_reporting_is_cancellable_and_requires_failed_dependencies(self):
        if not ROUTER:
            self.skipTest("router publish workflow required")
        jobs = yaml.safe_load((ROOT / MAIN).read_text())["jobs"]
        reporter = jobs["report-validation-failure"]
        report = next(step for step in reporter["steps"] if step.get("name") == "Report each distinct failure")
        self.assertEqual(report["env"]["REPORT_CANDIDATE_REF"], "${{ inputs.candidate_ref }}")
        self.assertEqual(report["env"]["REPORT_CANDIDATE_SHA"], "${{ inputs.candidate_sha }}")
        condition = reporter["if"]
        self.assertIn("!cancelled() &&", condition)
        self.assertNotIn("always()", condition)
        self.assertNotIn("!= 'success'", condition)
        for dependency in reporter["needs"]:
            self.assertIn(f"needs.{dependency}.result == 'failure'", condition)
        sonar = next(
            step for step in jobs["sonar"]["steps"]
            if step.get("name") == "Synchronize SonarQube findings"
        )
        self.assertIn("!cancelled() && failure()", sonar["if"])

    def test_pr_creation_and_later_updates_keep_the_release_app_identity(self):
        main = yaml.safe_load((ROOT / MAIN).read_text())
        caller = main["jobs"]["update-pr-branches"]
        self.assertEqual(caller["uses"], "./.github/workflows/pr-branch-updater.yml")
        self.assertEqual(caller["permissions"], {"contents": "read"})
        private_key = {"RELEASE_APP_PRIVATE_KEY": "${{ secrets.RELEASE_APP_PRIVATE_KEY }}"}
        self.assertEqual(caller["secrets"], private_key)
        release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        self.assertEqual(
            release["jobs"]["release"]["secrets"]["RELEASE_APP_PRIVATE_KEY"],
            private_key["RELEASE_APP_PRIVATE_KEY"],
        )
        for workflow in [main, yaml.safe_load((ROOT / caller["uses"]).read_text())]:
            events = workflow.get("on", workflow.get(True))
            self.assertIn("RELEASE_APP_PRIVATE_KEY", events["workflow_call"]["secrets"])
        updater = yaml.safe_load((ROOT / caller["uses"]).read_text())
        events = updater.get("on", updater.get(True))
        self.assertEqual(events["workflow_call"]["inputs"], {
            "refresh_mode": {"type": "string", "default": "automatic"},
        })
        self.assertEqual(events["workflow_dispatch"]["inputs"], {
            "pull_number": {
                "description": "PR number to refresh against the selected base branch",
                "type": "string",
                "required": True,
            },
        })
        self.assertEqual(updater["permissions"], {"contents": "read"})
        job = updater["jobs"]["update"]
        self.assertEqual(job["env"], {
            "PR_REFRESH_MODE": "${{ inputs.refresh_mode || 'manual' }}",
            "PR_REFRESH_NUMBER": "${{ inputs.pull_number || '' }}",
        })
        self.assertEqual(job["environment"], "release-automation")
        self.assertEqual(
            job["if"],
            "(github.event_name == 'push' || github.event_name == 'workflow_dispatch') && "
            "(github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/heads/release/'))",
        )
        steps = {step.get("name"): step for step in job["steps"]}
        checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
        self.assertEqual(checkout["with"]["ref"], "${{ github.workflow_sha }}")
        self.assertIs(checkout["with"]["persist-credentials"], False)
        preflight = steps["Validate updater context"]
        token = steps["Release App token"]
        self.assertLess(job["steps"].index(preflight), job["steps"].index(token))
        self.assertIn(".validateContext(context, {", preflight["with"]["script"])
        for step in [preflight, steps["Update open PR branches"]]:
            self.assertIn(
                "mode: process.env.PR_REFRESH_MODE, pullNumber: process.env.PR_REFRESH_NUMBER",
                step["with"]["script"],
            )
            self.assertNotIn("context.payload.inputs", step["with"]["script"])
        self.assertRegex(token["uses"], r"^actions/create-github-app-token@[0-9a-f]{40}$")
        self.assertEqual(token["id"], "app")
        self.assertEqual(token["with"], {
            "client-id": "${{ vars.RELEASE_APP_ID }}",
            "private-key": private_key["RELEASE_APP_PRIVATE_KEY"],
            "owner": "${{ github.repository_owner }}",
            "repositories": "${{ github.event.repository.name }}",
            "permission-contents": "write",
            "permission-pull-requests": "write",
        })
        followup = main["jobs"]["release-followup"]
        creation = next(
            step for step in followup["steps"]
            if step.get("name") == "Open the next version bump pull request"
        )
        for mutation in [creation, steps["Update open PR branches"]]:
            self.assertEqual(mutation["with"]["github-token"], "${{ steps.app.outputs.token }}")
        validation = yaml.safe_load((ROOT / ".github/workflows/pr-validation.yml").read_text())
        for pr_job in validation["jobs"].values():
            self.assertNotEqual(pr_job.get("uses"), caller["uses"])
            self.assertNotIn("secrets", pr_job)

    def test_pr_updater_authentication_regressions_fail_policy(self):
        path = ".github/workflows/pr-branch-updater.yml"
        original = (ROOT / path).read_text()
        for changed in [
            original.replace("github-token: ${{ steps.app.outputs.token }}", "github-token: ${{ github.token }}"),
            original.replace(".validateContext(context, {", ".validateContext({}, {"),
            original.replace("permission-pull-requests: write", "permission-pull-requests: read"),
            original.replace("default: automatic", "default: manual"),
            original.replace("inputs.refresh_mode || 'manual'", "github.event_name == 'workflow_dispatch' && 'manual' || 'automatic'"),
            original.replace("pullNumber: process.env.PR_REFRESH_NUMBER", "pullNumber: context.payload.inputs.pull_number"),
        ]:
            with self.subTest(workflow=changed):
                self.assertNotEqual(changed, original)
                self.assertTrue(policy({path: changed}))

    def test_cancellation_reporting_regressions_fail_policy(self):
        if not ROUTER:
            self.skipTest("router publish workflow required")
        original = (ROOT / MAIN).read_text()
        for changed in [
            original.replace("!cancelled() &&", "always() &&"),
            original.replace("needs.aislop.result == 'failure'", "needs.aislop.result != 'success'"),
        ]:
            with self.subTest(workflow=changed):
                self.assertTrue(policy({MAIN: changed}))

    def test_candidate_checkout_and_scanning_do_not_inherit_the_main_source(self):
        main = yaml.safe_load((ROOT / MAIN).read_text())
        for job in ["quality", "aislop", "codeql", "architecture"]:
            caller = main["jobs"][job]
            expected = {
                "candidate_sha": "${{ inputs.candidate_sha }}",
                "candidate_ref": "${{ inputs.candidate_ref }}",
            }
            if job == "architecture":
                expected["validation_only"] = "${{ inputs.validation_only == true }}"
            self.assertEqual(caller["with"], expected)
            workflow = yaml.safe_load((ROOT / caller["uses"]).read_text())
            for reusable in workflow["jobs"].values():
                for step in reusable.get("steps", []):
                    if step.get("uses", "").startswith("actions/checkout@") and "repository" not in step.get("with", {}):
                        self.assertEqual(step["with"]["ref"], "${{ inputs.candidate_sha }}")
                    if step.get("uses", "").startswith(("github/codeql-action/analyze@", "github/codeql-action/upload-sarif@")) and job != "quality":
                        self.assertEqual(step["with"]["sha"], "${{ inputs.candidate_sha }}")
                        self.assertEqual(step["with"]["ref"], "${{ inputs.candidate_ref }}")
        publisher = main["jobs"]["publish"]
        self.assertEqual(publisher["env"]["SOURCE_SHA"], "${{ inputs.candidate_sha || github.sha }}")
        self.assertNotIn("GITHUB_SHA", publisher["env"])
        steps = {step.get("name"): step for step in publisher["steps"]}
        self.assertEqual(steps["Upload Trivy SARIF"]["with"]["sha"], "${{ inputs.candidate_sha || github.sha }}")
        for name in ["Attest GHCR image", "Attest Docker Hub image"]:
            self.assertEqual(steps[name]["env"]["ATTEST_PREDICATE"], "${{ steps.provenance.outputs.path }}")
            self.assertEqual(steps[name]["env"]["ATTEST_TYPE"], "${{ steps.provenance.outputs.type }}")

    def test_two_validation_stages_keep_artifacts_distinct(self):
        ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        steps = {step.get("name"): step for job in ci["jobs"].values() for step in job.get("steps", [])}
        self.assertIn('--redact', steps["Gitleaks"]["run"])
        self.assertNotIn("uses", steps["Gitleaks"])
        upload = steps["Upload redacted secret scan"]
        self.assertIn("inputs.candidate_sha || github.sha", upload["with"]["name"])
        self.assertIn("github.run_attempt", upload["with"]["name"])
        architecture = yaml.safe_load((ROOT / ".github/workflows/architecture.yml").read_text())
        pages = next(step for step in architecture["jobs"]["validate"]["steps"] if step.get("name") == "Upload architecture Pages artifact")
        self.assertIn("inputs.candidate_sha == ''", pages["if"])
        self.assertEqual(pages["with"]["name"], "${{ steps.pages-artifact.outputs.name }}")
        outputs = architecture.get("on", architecture.get(True))["workflow_call"]["outputs"]
        self.assertEqual(outputs["pages_artifact_name"]["value"], "${{ jobs.validate.outputs.pages_artifact_name }}")
        main = yaml.safe_load((ROOT / MAIN).read_text())
        deploy = main["jobs"]["pages"]["steps"][0]
        self.assertEqual(deploy["with"]["artifact_name"], "${{ needs.architecture.outputs.pages_artifact_name }}")
        for filename in [MAIN, ".github/workflows/ci.yml", ".github/workflows/architecture.yml"]:
            workflow = yaml.safe_load((ROOT / filename).read_text())
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    if step.get("uses", "").startswith("actions/upload-artifact@"):
                        name = step["with"]["name"]
                        self.assertIn("candidate_sha", name)
                        if not name.startswith("image-${{"):
                            self.assertIn("github.run_attempt", name)

    def test_authoritative_coverage_handoff_is_same_run_and_before_sonar_secrets(self):
        ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        python = ci["jobs"]["python"]
        steps = python["steps"]
        indexed = {step.get("name"): index for index, step in enumerate(steps)}
        self.assertLess(indexed["Tests and coverage"], indexed["Prepare authoritative coverage evidence"])
        self.assertLess(indexed["Prepare authoritative coverage evidence"], indexed["Upload authoritative coverage evidence"])
        self.assertLess(indexed["Upload authoritative coverage evidence"], indexed["Record successful validation"])
        prepare = steps[indexed["Prepare authoritative coverage evidence"]]
        upload = steps[indexed["Upload authoritative coverage evidence"]]
        self.assertEqual(prepare["run"].splitlines(), [
            "python -m coverage xml",
            'python .github/scripts/coverage-artifact.py prepare "$RUNNER_TEMP/coverage-evidence"',
        ])
        self.assertEqual(prepare["env"], {
            "SOURCE_SHA": "${{ github.sha }}", "CANDIDATE_SHA": "${{ inputs.candidate_sha }}",
            "PRODUCER_RUN_ATTEMPT": "${{ github.run_attempt }}",
        })
        for step in [prepare, upload]:
            self.assertIn("success()", step["if"])
            self.assertNotIn("continue-on-error", step)
        self.assertEqual(prepare["if"], upload["if"])
        self.assertTrue(upload["uses"].startswith("actions/upload-artifact@"))
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertNotIn("overwrite", upload["with"])
        for identity in ["inputs.candidate_sha || github.sha", "github.run_attempt", "steps.coverage-evidence.outputs.config_sha256"]:
            self.assertIn(identity, upload["with"]["name"])
        self.assertEqual(upload["with"]["path"].splitlines(), [
            "${{ runner.temp }}/coverage-evidence/coverage.xml",
            "${{ runner.temp }}/coverage-evidence/manifest.json",
        ])
        outputs = ci.get("on", ci.get(True))["workflow_call"]["outputs"]
        for name in ["coverage_artifact_id", "coverage_run_attempt"]:
            self.assertEqual(outputs[name]["value"], "${{ jobs.python.outputs." + name + " }}")
        for event, ref, candidate, affected, state, allowed in [
            ("push", "refs/heads/main", "", "true", "success", True),
            ("workflow_dispatch", "refs/heads/main", "", "true", "success", True),
            ("workflow_dispatch", "refs/heads/main", "a" * 40, "true", "success", False),
            ("pull_request", "refs/pull/1/merge", "", "true", "success", False),
            ("push", "refs/heads/topic", "", "true", "success", False),
            ("push", "refs/heads/main", "", "false", "success", False),
            ("push", "refs/heads/main", "", "true", "failure", False),
            ("push", "refs/heads/main", "", "true", "cancelled", False),
        ]:
            with self.subTest(event=event, ref=ref, candidate=candidate, state=state):
                needs = {"changes": {"result": state, "outputs": {"python": affected}}}
                self.assertEqual(workflow_condition(prepare["if"], {"candidate_sha": candidate}, event, ref, needs), allowed)
        sonar = yaml.safe_load((ROOT / MAIN).read_text())["jobs"]["sonar"]
        self.assertEqual(sonar["needs"], ["quality", "aislop", "codeql", "architecture"])
        self.assertEqual(sonar["permissions"], {"contents": "read", "id-token": "write", "issues": "write"})
        self.assertEqual(sonar["env"], {
            "SOURCE_SHA": "${{ github.sha }}", "CANDIDATE_SHA": "${{ inputs.candidate_sha }}",
            "COVERAGE_ARTIFACT_ID": "${{ needs.quality.outputs.coverage_artifact_id }}",
            "PRODUCER_RUN_ATTEMPT": "${{ needs.quality.outputs.coverage_run_attempt }}",
        })
        steps = sonar["steps"]
        indexed = {step.get("name"): index for index, step in enumerate(steps)}
        self.assertLess(indexed["Set up Python"], indexed["Require authoritative coverage producer"])
        self.assertLess(indexed["Require authoritative coverage producer"], indexed["Download authoritative coverage"])
        self.assertLess(indexed["Download authoritative coverage"], indexed["Verify authoritative coverage"])
        verify = steps[indexed["Verify authoritative coverage"]]
        self.assertEqual(verify["run"], 'python .github/scripts/coverage-artifact.py restore "$RUNNER_TEMP/coverage-evidence"')
        download = steps[indexed["Download authoritative coverage"]]
        self.assertTrue(download["uses"].startswith("actions/download-artifact@"))
        self.assertEqual(download["with"], {
            "artifact-ids": "${{ needs.quality.outputs.coverage_artifact_id }}",
            "path": "${{ runner.temp }}/coverage-evidence", "digest-mismatch": "error",
        })
        for index, step in enumerate(steps):
            if "secrets." in json.dumps(step) or step.get("name") == "Connect to the tailnet":
                self.assertGreater(index, indexed["Verify authoritative coverage"])
            self.assertNotIn("continue-on-error", step)
            self.assertNotIn("pip install", step.get("run", ""))
            self.assertNotIn("pytest", step.get("run", ""))
        setup = steps[indexed["Set up Python"]]
        self.assertEqual(setup["with"], {"python-version": "3.12"})
        self.assertNotIn("Generate coverage for SonarQube", indexed)
        self.assertEqual(steps[indexed["SonarQube quality gate"]]["with"], {"pollingTimeoutSec": 270})
        self.assertEqual(steps[indexed["SonarQube quality gate"]]["timeout-minutes"], 6)
        findings = steps[indexed["Synchronize SonarQube findings"]]
        self.assertEqual(findings["if"], "${{ !cancelled() && failure() && steps.sonar-quality-gate.outcome == 'failure' }}")

    def test_sonar_missing_producer_outputs_fail_before_artifact_download(self):
        sonar = yaml.safe_load((ROOT / MAIN).read_text())["jobs"]["sonar"]
        guard = next(step for step in sonar["steps"] if step.get("name") == "Require authoritative coverage producer")
        for artifact_id, attempt, success in [("123", "1", True), ("", "1", False),
                                              ("123", "", False), ("0", "1", False),
                                              ("123,456", "1", False), ("123", "bad", False)]:
            with self.subTest(artifact_id=artifact_id, attempt=attempt):
                result = subprocess.run(["bash", "-eo", "pipefail", "-c", guard["run"]],
                                        env={**os.environ, "COVERAGE_ARTIFACT_ID": artifact_id,
                                             "PRODUCER_RUN_ATTEMPT": attempt},
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode == 0, success)
                if not success:
                    self.assertIn("CoverageEvidenceError:", result.stderr)
                    self.assertIn("rerun authoritative main CI", result.stderr)

    def test_coverage_verifier_and_tests_are_protected(self):
        for path in [".github/scripts/coverage-artifact.py", ".github/scripts/coverage-artifact.test.py"]:
            with self.subTest(path=path):
                self.assertTrue(policy({path: (ROOT / path).read_text() + "\n# unreviewed change\n"}))

    def test_ste_workflow_replacement_fails_reviewed_policy(self):
        if not ROUTER:
            self.skipTest("router STE workflow required")
        path = ".github/workflows/docs-ste.yml"
        replacement = """name: docs-ste
on:
  workflow_call:
permissions:
  contents: read
jobs:
  pass:
    runs-on: ubuntu-latest
    steps:
      - run: echo passed
"""
        self.assertEqual(policy(), [])
        self.assertIn(
            f"{path}: owner review cannot change the trusted workflow execution contract",
            "\n".join(policy({path: replacement})),
        )

    def test_reviewed_release_workflows_pass(self):
        self.assertEqual(policy(), [])

    def test_main_publishing_and_release_gate_bypass_fail(self):
        original = (ROOT / MAIN).read_text()
        mutations = [
            original.replace(
                "inputs.candidate_sha != ''", "github.ref == 'refs/heads/main'"
            ),
            original.replace(
                "      - name: Release preflight",
                "      - if: false\n        name: Release preflight",
            ),
            original.replace("needs: [quality, aislop, codeql", "needs: [quality, codeql"),
        ]
        for content in mutations:
            with self.subTest(content=content[:30]):
                self.assertNotEqual(content, original)
                self.assertTrue(policy({MAIN: content}))

    def test_dependabot_dispatch_target_validates_main_without_release_inputs(self):
        automation = yaml.safe_load((ROOT / ".github/workflows/dependabot-auto-merge.yml").read_text())
        dispatch = next(
            step["with"]["script"]
            for step in automation["jobs"]["enable-auto-merge"]["steps"]
            if "script" in step.get("with", {})
        )
        target = re.search(r"mainWorkflow: '([^']+)'", dispatch).group(1)
        self.assertEqual(f".github/workflows/{target}", MAIN)
        jobs = yaml.safe_load((ROOT / MAIN).read_text())["jobs"]
        for name in ["quality", "aislop", "codeql", "architecture"]:
            self.assertEqual(jobs[name]["if"], "github.ref == 'refs/heads/main' || inputs.candidate_sha != ''")
        for name in ["pages", "sonar", "update-pr-branches", "publish", "report-validation-failure"]:
            self.assertIn("github.ref == 'refs/heads/main'", jobs[name]["if"])
        for name in ["cleanup", "release-followup"]:
            self.assertIn("inputs.candidate_sha != ''", jobs[name]["if"])

    def test_automatic_release_push_and_manual_candidate_inputs_fail_policy(self):
        release = ".github/workflows/release.yml"
        main = (ROOT / MAIN).read_text()
        self.assertTrue(policy({MAIN: main.replace(
            "  workflow_dispatch:",
            "  workflow_dispatch:\n    inputs:\n      candidate_sha:\n        type: string",
        )}))
        self.assertTrue(policy({release: (ROOT / release).read_text().replace(
            "  workflow_dispatch:", "  push:\n    branches: ['release/*']")}))

    def test_release_script_mutation_fails(self):
        path = ".github/scripts/release.cjs"
        self.assertTrue(
            policy({path: (ROOT / path).read_text().replace("if (!condition)", "if (false)")})
        )

    def test_attestation_verification_and_regression_checks_cannot_be_neutralized(self):
        if not ROUTER:
            self.skipTest("router attestation helpers required")
        mutations = [
            ("provenance.cjs", 'issuer: ISSUER, audience: AUDIENCE, algorithms: ["RS256"],', ''),
            ("attest-image.cjs", '  run("gh", [...verify, "--bundle", bundlePath]);', ''),
            ("provenance.test.cjs", 'test("', 'test.skip("'),
            ("attest-image.test.cjs", 'test("', 'test.skip("'),
            ("attestation-smoke.sh", "cosign verify-attestation", "true verify-attestation"),
        ]
        for filename, before, after in mutations:
            path = f".github/scripts/{filename}"
            with self.subTest(path=path):
                original = (ROOT / path).read_text()
                changed = original.replace(before, after, 1)
                self.assertNotEqual(changed, original)
                self.assertIn(
                    f"{path}: release automation must match its reviewed policy",
                    "\n".join(policy({path: changed})),
                )

    def test_scanners_use_separate_fixed_tools_and_candidate_source(self):
        for filename, job in [("ci.yml", "security"), ("aislop.yml", "status")]:
            steps = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())["jobs"][job]["steps"]
            named = {step.get("name"): step for step in steps}
            trusted = named["Check out trusted scanner implementation"]["with"]
            self.assertEqual(trusted["repository"], "mickey-kras/hindsight-memory-router")
            self.assertEqual(trusted["ref"], "f42f81fdd308b1361a24db1a45fec411b0801eae")
            self.assertEqual(trusted["path"], "trusted")
            self.assertFalse(trusted["persist-credentials"])
            candidate = named["Check out candidate source"]["with"]
            self.assertEqual(candidate["ref"], "${{ inputs.candidate_sha }}")
            self.assertEqual(candidate["path"], "candidate")
            self.assertEqual(candidate["fetch-depth"], 0)
            self.assertFalse(candidate["persist-credentials"])
            self.assertTrue(all(not step.get("continue-on-error") for step in steps))
        security = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]["security"]["steps"]
        named = {step.get("name"): step for step in security}
        self.assertIn("--disable-pip", named["Python dependency audit"]["run"])
        self.assertIn("--require-hashes", named["Python dependency audit"]["run"])
        self.assertIn("--no-git-ignore --disable-nosem", named["Semgrep"]["run"])
        self.assertIn("trusted/.semgrep.yml:/policy/semgrep.yml:ro", named["Semgrep"]["run"])
        self.assertIn("--log-opts=\"--full-history --all --text\"", named["Gitleaks"]["run"])
        self.assertIn("--redact --ignore-gitleaks-allow", named["Gitleaks"]["run"])
        audit = named["Node tooling audit"]
        self.assertEqual(audit["env"]["npm_config_registry"], "https://registry.npmjs.org")
        self.assertEqual(audit["env"]["npm_config_userconfig"], "/dev/null")
        self.assertEqual(audit["env"]["npm_config_globalconfig"], "/dev/null")
        for target in ["$RUNNER_TEMP/audits", "$RUNNER_TEMP/audits/ui", "$RUNNER_TEMP/audits/.github/scripts"]:
            self.assertIn(f'node trusted/.github/scripts/npm-audit.cjs "{target}"', audit["run"])
        self.assertNotIn("npm ci", "\n".join(step.get("run", "") for step in security))

    def test_scanner_source_substitution_fails_policy(self):
        for filename in ["ci.yml", "aislop.yml"]:
            path = f".github/workflows/{filename}"
            original = (ROOT / path).read_text()
            for old, new in [("f42f81fdd308b1361a24db1a45fec411b0801eae", "${{ github.sha }}"),
                             ("repository: mickey-kras/hindsight-memory-router", "repository: attacker/router"),
                             ("path: trusted", "path: candidate")]:
                with self.subTest(filename=filename, mutation=new):
                    changed = original.replace(old, new)
                    self.assertNotEqual(changed, original)
                    self.assertTrue(policy({path: changed}, paths=[path]))
        for path in [".aislop/config.yml", ".semgrep.yml", ".gitleaks.toml", ".gitleaksignore",
                     ".github/scripts/npm-audit.cjs", ".github/trusted-ci/scan-tree.cjs",
                     ".github/trusted-ci/aislop.mjs", ".github/trusted-ci/safe-path.cjs"]:
            with self.subTest(path=path):
                self.assertTrue(policy({path: (ROOT / path).read_text() + "\n# changed scanner policy\n"}, paths=[path]))

    def test_scan_neutralization_fails(self):
        path = ".github/workflows/ci.yml"
        name = "Trivy PR gate" if ROUTER else "Trivy dependency gate"
        changed = (
            (ROOT / path)
            .read_text()
            .replace(
                f"      - name: {name}", f"      - continue-on-error: true\n        name: {name}"
            )
        )
        self.assertTrue(policy({path: changed}))

    def test_full_action_pin_refresh_is_allowed(self):
        doc = yaml.safe_load((ROOT / MAIN).read_text())
        action = next(
            step["uses"]
            for job in doc["jobs"].values()
            for step in job.get("steps", [])
            if "uses" in step
        )
        changed = (ROOT / MAIN).read_text().replace(action, action.split("@")[0] + "@" + "f" * 40)
        self.assertEqual(policy({MAIN: changed}), [])


class AdmissionPolicyTests(unittest.TestCase):
    lock_path = '.github/scripts/package-lock.json'
    source_path = '.github/scripts/release-settings.cjs'

    def lock_change(self, update):
        lock = json.loads((ROOT / self.lock_path).read_text())
        update(lock)
        return policy({self.lock_path: json.dumps(lock)}, paths=[self.lock_path])

    def test_registry_update_needs_no_hash_admission(self):
        def update(lock):
            entry = lock['packages']['node_modules/jose']
            entry['version'] = '6.2.13'
            entry['resolved'] = 'https://registry.npmjs.org/jose/-/jose-6.2.13.tgz'
        self.assertEqual(self.lock_change(update), [])

    def test_lockfile_rejects_untrusted_sources_integrity_and_scripts(self):
        for field, value in [
            ('resolved', 'https://registry.npmjs.org.evil.test/jose/-/jose.tgz'),
            ('resolved', 'https://registry.npmjs.org@evil.test/jose/-/jose.tgz'),
            ('resolved', 'http://registry.npmjs.org/jose/-/jose.tgz'),
            ('resolved', 'git+https://github.com/example/jose.git'),
            ('resolved', 'file:../../evil'),
            ('resolved', 'https://registry.npmjs.org/jose/-/jose.tgz?token=x'),
            ('resolved', 'https://registry.npmjs.org/other/-/other-6.2.12.tgz'),
            ('resolved', 'https://registry.npmjs.org/jose/-/jose-99.0.0.tgz'),
            ('name', 'other'), ('hasShrinkwrap', True), ('hasShrinkwrap', False),
            ('integrity', 'sha1-YWJj'), ('integrity', ''),
            ('hasInstallScript', True), ('hasInstallScript', 'false'),
            ('link', True), ('inBundle', True), ('bundled', False),
        ]:
            with self.subTest(field=field, value=value):
                self.assertTrue(self.lock_change(lambda lock: lock['packages']['node_modules/jose'].__setitem__(field, value)))
        self.assertTrue(self.lock_change(lambda lock: lock['packages']['node_modules/jose'].pop('integrity')))
        self.assertTrue(self.lock_change(lambda lock: lock['packages']['']['dependencies'].__setitem__('jose', '*')))
        self.assertTrue(self.lock_change(lambda lock: lock.__setitem__('lockfileVersion', 2)))

    def test_existing_install_script_does_not_admit_another_dependency(self):
        original = json.loads((ROOT / self.lock_path).read_text())
        original['packages']['node_modules/jose']['hasInstallScript'] = True
        modified = json.loads(json.dumps(original))
        modified['packages']['node_modules/semver']['hasInstallScript'] = True
        self.assertTrue(policy({self.lock_path: json.dumps(modified)}, paths=[self.lock_path],
                               base_overrides={self.lock_path: json.dumps(original)}))
        self.assertEqual(policy({self.lock_path: json.dumps(original)}, paths=[self.lock_path],
                                base_overrides={self.lock_path: json.dumps(original)}), [])

    def test_existing_alias_remains_bound_to_its_original_package(self):
        original = json.loads((ROOT / self.lock_path).read_text())
        name = 'node_modules/jose/node_modules/legacy-name'
        original['packages'][name] = {**original['packages']['node_modules/jose'], 'name': 'jose'}
        self.assertEqual(policy({self.lock_path: json.dumps(original)}, paths=[self.lock_path],
                                base_overrides={self.lock_path: json.dumps(original)}), [])
        self.assertTrue(policy({self.lock_path: json.dumps(original)}, paths=[self.lock_path]))
        modified = json.loads(json.dumps(original))
        modified['packages'][name]['name'] = 'other'
        modified['packages'][name]['resolved'] = 'https://registry.npmjs.org/other/-/other-6.2.12.tgz'
        self.assertTrue(policy({self.lock_path: json.dumps(modified)}, paths=[self.lock_path],
                               base_overrides={self.lock_path: json.dumps(original)}))

    def admission(self, reviews=None, rules=None, user=None, base_overrides=None, **kwargs):
        return policy({self.source_path: (ROOT / self.source_path).read_text() + '\n// reviewed update\n'},
                      paths=[self.source_path], reviews=reviews, rules=rules,
                      pull={'number': 1, 'state': 'open', 'head': {'sha': 'a' * 40}, 'base': {'sha': 'b' * 40, 'ref': 'main'},
                            'user': user or {'login': 'implementer[bot]', 'type': 'Bot', 'id': 123}},
                      base_overrides=base_overrides, **kwargs)

    def approval(self, **values):
        return {'id': 1, 'user': {'login': 'mickey-kras', 'type': 'User', 'id': 24433677}, 'state': 'APPROVED', 'commit_id': 'a' * 40, **values}

    def rules(self):
        return [{'type': 'pull_request', 'ruleset_id': 42, 'ruleset_source_type': 'Repository', 'ruleset_source': 'test/test',
                 'parameters': {'require_code_owner_review': True,
                 'dismiss_stale_reviews_on_push': True, 'require_last_push_approval': True,
                 'required_approving_review_count': 1}}]

    def source(self, **values):
        return {'42': {'id': 42, 'source_type': 'Repository', 'source': 'test/test', 'enforcement': 'active',
                       'target': 'branch', 'updated_at': '2026-10-23T00:00:00Z', 'rules': self.rules(),
                       'bypass_actors': [], **values}}

    def settings_review(self, **values):
        return json.dumps({'repository': 'test/test', 'ruleset_id': 42, 'updated_at': '2026-10-23T00:00:00Z',
                           'bypass_actors': [], **values})

    def test_review_source_bypasses_and_redaction_fail_closed(self):
        args = ([self.approval()], self.rules())
        for bypasses in [[{'actor_type': 'Integration', 'actor_id': 123, 'bypass_mode': 'pull_request'}], None, {}, '']:
            with self.subTest(bypasses=bypasses):
                self.assertTrue(self.admission(*args, sources=self.source(bypass_actors=bypasses),
                                               settings_review=self.settings_review()))
        redacted = self.source()
        del redacted['42']['bypass_actors']
        for review in ['', '{}', 'null', '[]', '{', self.settings_review(repository='other/test'),
                       self.settings_review(ruleset_id=43), self.settings_review(ruleset_id='42'),
                       self.settings_review(updated_at='2026-10-22T00:00:00Z'), self.settings_review(bypass_actors=[{}])]:
            with self.subTest(review=review):
                self.assertTrue(self.admission(*args, sources=redacted, settings_review=review))
        self.assertEqual(self.admission(*args, sources=redacted, settings_review=self.settings_review()), [])
        redacted['42']['updated_at'] = '2026-10-23T00:00:01Z'
        self.assertTrue(self.admission(*args, sources=redacted, settings_review=self.settings_review()))

    def test_review_source_must_still_enforce_the_applicable_review_rule(self):
        for values in [{'enforcement': 'disabled'}, {'enforcement': 'evaluate'}, {'target': 'tag'}, {'id': 43},
                       {'source_type': 'Organization'}, {'source': 'other/test'}, {'rules': []},
                       {'rules': [{'type': 'pull_request', 'parameters': {'required_approving_review_count': 1}}]}]:
            with self.subTest(values=values):
                self.assertTrue(self.admission([self.approval()], self.rules(), sources=self.source(**values),
                                               settings_review=self.settings_review()))
        for values in [{'ruleset_id': 0}, {'ruleset_id': '42'}, {'ruleset_source_type': 'Organization'},
                       {'ruleset_source': 'other/test'}]:
            rules = [{**self.rules()[0], **values}]
            self.assertTrue(self.admission([self.approval()], rules))

    def test_exact_head_owner_admission_requires_independent_bot_and_live_controls(self):
        self.assertEqual(self.admission([self.approval()], self.rules()), [])
        self.assertTrue(self.admission([self.approval()], []))
        self.assertTrue(self.admission([], self.rules()))
        for key in self.rules()[0]['parameters']:
            rules = self.rules()
            rules[0]['parameters'][key] = False
            self.assertTrue(self.admission([self.approval()], rules))
        for user in [{'login': 'mickey-kras', 'type': 'User'}, {'login': 'someone', 'type': 'User'},
                     {'login': 'mickey-kras', 'type': 'Bot'}]:
            self.assertTrue(self.admission([self.approval()], self.rules(), user))
        self.assertTrue(self.admission([self.approval()], self.rules(), base_overrides={'.github/CODEOWNERS': '/.github/ @someone\n'}))

    def test_stale_revoked_and_nonowner_reviews_cannot_admit(self):
        for review in [self.approval(commit_id='c' * 40), self.approval(state='DISMISSED'),
                       self.approval(user={'login': 'someone', 'type': 'User'}),
                       self.approval(user={'login': 'mickey-kras', 'type': 'User', 'id': 999})]:
            self.assertTrue(self.admission([review], self.rules()))
        for state in ['DISMISSED', 'CHANGES_REQUESTED']:
            self.assertTrue(self.admission([self.approval(), self.approval(id=2, state=state)], self.rules()))
        self.assertEqual(self.admission([self.approval(), self.approval(id=2, state='COMMENTED')], self.rules()), [])

    def test_npm_configuration_and_shadow_locks_are_rejected_without_lock_changes(self):
        for path in ['.npmrc', '.github/.npmrc', '.github/scripts/.npmrc', '.github/scripts/npm-shrinkwrap.json']:
            with self.subTest(path=path):
                result = policy(paths=[path], reviews=[self.approval()], rules=self.rules(),
                                pull={'number': 1, 'state': 'open', 'head': {'sha': 'a' * 40},
                                      'base': {'sha': 'b' * 40, 'ref': 'main'},
                                      'user': {'login': 'implementer[bot]', 'type': 'Bot', 'id': 123}})
                self.assertIn('must not override the registry or governed lockfile', '\n'.join(result))

    def test_owner_approval_cannot_disable_workflow_execution(self):
        path = '.github/workflows/ci.yml'
        original = (ROOT / path).read_text()
        changes = [
            original.replace('      - name: Gitleaks\n', '      - name: Gitleaks\n        if: false\n'),
            original.replace('      - name: Gitleaks\n', '      - name: Gitleaks\n        continue-on-error: true\n'),
            original.replace('        run: bandit --ini /dev/null -q -r', '        run: true'),
            original.replace('--config trusted/.gitleaks.toml', '--config candidate/.gitleaks.toml'),
            original.replace('  security:\n', '  security:\n    continue-on-error: true\n'),
        ]
        for changed in changes:
            self.assertNotEqual(changed, original)
            result = policy({path: changed}, paths=[path], reviews=[self.approval()], rules=self.rules(),
                            pull={'number': 1, 'state': 'open', 'head': {'sha': 'a' * 40},
                                  'base': {'sha': 'b' * 40, 'ref': 'main'},
                                  'user': {'login': 'implementer[bot]', 'type': 'Bot', 'id': 123}})
            self.assertIn('cannot change the trusted workflow execution contract', '\n'.join(result))

    def test_owner_approval_can_add_steps_without_replacing_existing_controls(self):
        path = '.github/workflows/ci.yml'
        original = (ROOT / path).read_text()
        changed = original.replace('      - name: Gitleaks\n', '      - name: Supplementary check\n        run: echo supplementary\n      - name: Gitleaks\n')
        args = {'paths': [path], 'reviews': [self.approval()], 'rules': self.rules(),
                'pull': {'number': 1, 'state': 'open', 'head': {'sha': 'a' * 40},
                         'base': {'sha': 'b' * 40, 'ref': 'main'},
                         'user': {'login': 'implementer[bot]', 'type': 'Bot', 'id': 123}}}
        self.assertEqual(policy({path: changed}, **args), [])
        self.assertTrue(policy({path: changed}, **{**args, 'reviews': []}))
        extra_job = original + '\n  supplemental:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo supplementary\n'
        self.assertEqual(policy({path: extra_job}, **args), [])

    def test_live_pull_changes_fail_closed_after_validation(self):
        ready = {'state': 'open', 'head': {'sha': 'a' * 40}, 'base': {'sha': 'b' * 40}}
        self.assertEqual(policy(paths=[self.source_path], current_pull=ready), [])
        for current in [{**ready, 'head': {'sha': 'c' * 40}},
                        {**ready, 'base': {'sha': 'c' * 40}}, {**ready, 'state': 'closed'}]:
            with self.subTest(current=current), self.assertRaises(subprocess.CalledProcessError):
                policy(paths=[self.source_path], current_pull=current)

    def test_owner_approval_cannot_remove_the_guard(self):
        path = '.github/workflows/policy-guard.yml'
        result = policy(paths=[path], statuses={path: 'removed'}, reviews=[self.approval()], rules=self.rules(),
                        pull={'number': 1, 'state': 'open', 'head': {'sha': 'a' * 40},
                              'base': {'sha': 'b' * 40, 'ref': 'main'},
                              'user': {'login': 'implementer[bot]', 'type': 'Bot', 'id': 123}})
        self.assertIn('protected policy must not be removed', '\n'.join(result))

    def test_guard_is_base_owned_and_lock_hash_cannot_return(self):
        workflow = yaml.safe_load(GUARD.read_text())
        self.assertEqual(set(workflow.get('on', workflow.get(True))), {'pull_request_target'})
        self.assertEqual(workflow['jobs']['guard']['name'], 'guard / guard')
        self.assertEqual(workflow['permissions'], {'contents': 'read', 'pull-requests': 'read'})
        steps = workflow['jobs']['guard']['steps']
        checkouts = [step for step in steps if step.get('uses', '').startswith('actions/checkout@')]
        self.assertEqual(len(checkouts), 1)
        self.assertEqual(checkouts[0]['with'], {'ref': '${{ github.workflow_sha }}', 'path': '.policy-tools',
                                               'sparse-checkout': '.github/scripts', 'persist-credentials': False})
        install = next(step for step in steps if step.get('name') == 'Install trusted policy parser')
        self.assertEqual(install['working-directory'], '.policy-tools/.github/scripts')
        self.assertEqual(install['run'], 'npm ci --ignore-scripts --registry=https://registry.npmjs.org --userconfig=/dev/null')
        source = next(step['with']['script'] for step in steps if 'script' in step.get('with', {}))
        pins = source.split('const releaseProtected = {', 1)[1].split('};', 1)[0]
        self.assertNotIn('package-lock.json', pins)
        self.assertNotRegex(pins, r':\s*\[')
        self.assertNotIn('guard', yaml.safe_load((ROOT / '.github/workflows/pr-validation.yml').read_text())['jobs'])


if __name__ == "__main__":
    unittest.main()

