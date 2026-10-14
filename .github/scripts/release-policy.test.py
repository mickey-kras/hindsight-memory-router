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
    ".github/scripts/aislop-cli.test.cjs",
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
        ".github/scripts/provenance.cjs",
        ".github/scripts/provenance.test.cjs",
        ".github/scripts/attest-image.cjs",
        ".github/scripts/attest-image.test.cjs",
        ".github/scripts/attestation-smoke.sh",
    ])


def policy(overrides=None):
    files = {
        str(path.relative_to(ROOT)): path.read_text()
        for path in (ROOT / ".github").rglob("*")
        if path.is_file() and path.suffix in {".yml", ".yaml", ".cjs", ".py", ".sh", ".json"}
    }
    files["package.json"] = (ROOT / "package.json").read_text()
    files.update(overrides or {})
    guard = yaml.safe_load(GUARD.read_text())
    steps = guard["jobs"]["guard"]["steps"]
    if ROUTER:
        script = next(step["with"]["script"] for step in steps if "with" in step)
        driver = r"""
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const failures = [];
const github = { paginate: async () => input.paths.map(filename => ({filename, status: 'modified'})),
  rest: { pulls: {listFiles() {}}, repos: {getContent: async ({path}) => ({data: {
    content: Buffer.from(input.files[path]).toString('base64'), encoding: 'base64'
  }})}}};
const context = {repo: {owner: 'test', repo: 'test'}, payload: {pull_request: {number: 1, head: {sha: 'test'}}}};
const core = {setFailed: text => failures.push(text), info() {}};
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
new AsyncFunction('github', 'context', 'core', 'require', input.script)(github, context, core, require)
  .then(() => process.stdout.write(JSON.stringify(failures))).catch(error => {console.error(error); process.exit(1);});
"""
        result = subprocess.run(
            ["node", "-e", driver],
            input=json.dumps({"script": script, "files": files, "paths": PATHS}),
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


def quality_gate(needs, event="pull_request"):
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
        env={**os.environ, "NEEDS_JSON": json.dumps(needs), "EVENT_NAME": event},
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


class ReleasePolicyTests(unittest.TestCase):
    def test_parallel_quality_jobs_preserve_required_identities_and_hindsight(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        jobs = workflow["jobs"]
        self.assertEqual(workflow["name"], "ci")
        self.assertEqual(set(jobs), {"hindsight", "python", "ui", "release", "security", "checks", "container"})
        self.assertEqual(set(jobs["checks"]["needs"]), set(jobs) - {"checks"})
        self.assertEqual(jobs["checks"]["if"], "always()")
        self.assertEqual(jobs["checks"].get("name", "checks"), "checks")
        self.assertEqual(jobs["container"]["name"], "container")
        self.assertEqual(jobs["container"]["if"], "github.event_name == 'pull_request'")
        for name in ["ui", "release", "security"]:
            self.assertNotIn("needs", jobs[name])
        for name in ["python", "container"]:
            self.assertEqual(jobs[name]["needs"], "hindsight")
        for name in ["hindsight", "python", "ui", "release", "security"]:
            self.assertNotIn("if", jobs[name])
        for job in jobs.values():
            self.assertNotIn("continue-on-error", job)
            for step in job["steps"]:
                self.assertNotIn("continue-on-error", step)
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False)
        self.assertFalse(any(step.get("uses", "").startswith("actions/checkout@") for step in jobs["checks"]["steps"]))
        gate = jobs["checks"]["steps"][0]
        self.assertEqual(gate["env"], {"NEEDS_JSON": "${{ toJSON(needs) }}", "EVENT_NAME": "${{ github.event_name }}"})
        outputs = workflow.get("on", workflow.get(True))["workflow_call"]["outputs"]
        for name, source in [("version", "version"), ("sha", "sha"), ("image", "image")]:
            self.assertEqual(outputs[f"hindsight_{name}"]["value"], f"${{{{ jobs.hindsight.outputs.{source} }}}}")
        resolve = next(step for step in jobs["hindsight"]["steps"] if step.get("id") == "resolve")
        self.assertEqual(resolve["env"], {"RELEASE_CANDIDATE_SHA": "${{ inputs.candidate_sha }}", "RELEASE_CANDIDATE_REF": "${{ inputs.candidate_ref }}"})
        upstream = next(step for step in jobs["python"]["steps"] if step.get("name") == "Checkout current Hindsight OpenClaw sources")
        self.assertEqual(upstream["with"]["ref"], "${{ needs.hindsight.outputs.sha }}")
        self.assertEqual(jobs["container"]["env"]["HINDSIGHT_TEST_IMAGE"], "${{ needs.hindsight.outputs.image }}")

    def test_quality_gate_rejects_failed_cancelled_missing_and_skipped_jobs(self):
        names = ["hindsight", "python", "ui", "release", "security", "container"]
        passing = {name: {"result": "success", "outputs": {}} for name in names}
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

    def test_quality_gate_allows_only_the_known_non_pr_container_skip_and_reruns(self):
        passing = {name: {"result": "success"} for name in ["hindsight", "python", "ui", "release", "security", "container"]}
        for event in ["push", "workflow_dispatch"]:
            with self.subTest(event=event):
                baseline = {**passing, "container": {"result": "skipped"}}
                self.assertEqual(quality_gate(baseline, event), [])
                self.assertTrue(quality_gate({**baseline, "security": {"result": "skipped"}}, event))
                for state in ["success", "failure", "cancelled", None]:
                    self.assertTrue(quality_gate({**baseline, "container": {"result": state}}, event))
                self.assertTrue(quality_gate({key: value for key, value in baseline.items() if key != "container"}, event))
                self.assertTrue(quality_gate({**baseline, "python": {"result": "failure"}}, event))
                # A failed-job rerun may retain successful results from the first attempt.
                self.assertEqual(quality_gate(baseline, event), [])
        self.assertTrue(quality_gate({**passing, "ui": {"result": "cancelled"}}))
        self.assertEqual(quality_gate(passing), [])

    def test_quality_worker_gates_and_diagnostics_remain_local(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        required = {
            "python": ["Python runtime lock is current", "Python dev lock is current", "No legacy TypeScript runtime or tests", "OpenClaw compatibility inventory", "Unicode confusables map is reproducible", "Tests and coverage"],
            "ui": ["Aislop CLI regression tests", "UI unit, crypto, and build checks", "UI package consumer check", "Install Playwright Chromium", "UI browser tests", "OpenAPI contract", "Upload OpenAPI diagnostics"],
            "release": ["npm audit filter tests", "Release automation tests", "Attestation CLI and registry compatibility", "Release policy tests", "PR branch updater tests", "Failure reporter tests"],
            "security": ["Audit release tools", "Python dependency audit", "Bandit", "Node tooling audit", "Gitleaks", "Upload redacted secret scan", "Semgrep", "Hadolint"],
            "container": ["Default Compose smoke", "Fake Hindsight router-storage parity", "Real Hindsight router-storage parity", "Trivy PR gate"],
        }
        for name, gates in required.items():
            steps = {step.get("name"): step for step in jobs[name]["steps"]}
            for gate in gates:
                self.assertIn(gate, steps)
        coverage = next(step for step in jobs["python"]["steps"] if step.get("name") == "Tests and coverage")
        self.assertEqual(coverage["run"], "coverage run -m pytest && coverage report --fail-under=90")
        ui_steps = jobs["ui"]["steps"]
        npm_install = next(index for index, step in enumerate(ui_steps) if step.get("run") == "npm ci")
        aislop_test = next(index for index, step in enumerate(ui_steps) if step.get("name") == "Aislop CLI regression tests")
        self.assertLess(npm_install, aislop_test)
        self.assertEqual(ui_steps[aislop_test]["run"], "node --test .github/scripts/aislop-cli.test.cjs")
        self.assertNotIn("if", ui_steps[aislop_test])
        runtime_install = next(index for index, step in enumerate(ui_steps) if step.get("run") == "python -m pip install --require-hashes -r requirements.txt")
        ui_test = next(index for index, step in enumerate(ui_steps) if step.get("name") == "UI unit, crypto, and build checks")
        self.assertLess(runtime_install, ui_test)
        self.assertTrue(any(step.get("uses", "").startswith("actions/setup-python@") for step in ui_steps[:runtime_install]))
        for job in jobs.values():
            steps = {step.get("name"): step for step in job["steps"]}
            step_ids = {step["id"] for step in job["steps"] if "id" in step}
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
            original.replace("needs: [hindsight, python, ui, release, security, container]", "needs: [hindsight, python, ui, release, security]"),
            original.replace("result !== expected", "false"),
            original.replace("  security:\n", "  security:\n    continue-on-error: true\n"),
            original.replace("  ui:\n", "  ui:\n    if: false\n"),
            original.replace("coverage report --fail-under=90", "coverage report --fail-under=0"),
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
            npm = directory / "npm"
            npm.write_text("""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
with open('invocations.jsonl', 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
if os.environ['AISLOP_TEST_MISSING'] == 'true':
    Path('aislop.sarif').unlink(missing_ok=True)
else:
    sys.stdout.write(os.environ['AISLOP_TEST_REPORT'])
sys.stderr.write('scanner diagnostic\\n')
sys.exit(int(os.environ['AISLOP_TEST_EXIT']))
""")
            npm.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{directory}{os.pathsep}{os.environ['PATH']}",
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
            self.assertEqual(invocations, [["run", "--silent", "aislop:ci", "--", "--sarif"]])
            self.assertIn("scanner diagnostic", scan.stderr)
            if report is not None:
                expected = report if isinstance(report, str) else json.dumps(report)
                self.assertEqual((directory / "aislop.sarif").read_text(), expected)
            return scan, findings

    def test_aislop_single_scan_contract(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/aislop.yml").read_text())
        steps = workflow["jobs"]["status"]["steps"]
        scans = [step for step in steps if "aislop:ci" in step.get("run", "")]
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
        checkout = next(step for step in workflow["jobs"]["status"]["steps"] if step.get("uses", "").startswith("actions/checkout@"))
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
        for command in ["aislop:ci -- --human", "aislop:ci -- --sarif || true", "aislop:ci -- --sarif --changes"]:
            with self.subTest(command=command):
                changed = original.replace("aislop:ci -- --sarif", command)
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
        lock = json.loads((ROOT / ".github/scripts/package-lock.json").read_text())
        self.assertIn("jose", manifest["dependencies"])
        for package in ["@actions/attest", "http-cache-semantics", "make-fetch-happen"]:
            self.assertFalse(any(path.endswith("node_modules/" + package) for path in lock["packages"]))
        publish = yaml.safe_load((ROOT / MAIN).read_text())["jobs"]["publish"]
        steps = {step.get("name"): step for step in publish["steps"]}
        self.assertFalse(any(step.get("uses", "").startswith("actions/attest") for step in publish["steps"]))
        self.assertEqual(steps["Install Cosign"]["with"]["cosign-release"], "v3.1.3")
        upload = steps["Retain verified attestation bundles"]
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertIn("github.run_attempt", upload["with"]["name"])
        self.assertEqual(publish["permissions"]["attestations"], "write")

    def test_release_ui_package_contract(self):
        if not ROUTER:
            self.skipTest("router publish workflow required")
        publish = yaml.safe_load((ROOT / MAIN).read_text())["jobs"]["publish"]
        steps = {step.get("name"): step for step in publish["steps"]}
        gate = "steps.push.outputs.published == 'true'"
        for name in ["Build and pack the UI package", "Sign the UI package"]:
            expected = gate + " && steps.candidate.outputs.release_assets == ''" if name == "Sign the UI package" else gate
            self.assertEqual(steps[name]["if"], expected)
        build = steps["Build and pack the UI package"]["run"]
        self.assertIn("npm ci --prefix ui", build)
        self.assertIn("npm pack ./ui", build)
        sign = steps["Sign the UI package"]
        self.assertIn("cosign sign-blob --yes", sign["run"])
        self.assertIn("--bundle", sign["run"])
        self.assertIn(".sigstore.json", sign["run"])
        self.assertIn("ui-package=sha256:", steps["Record image digests"]["run"])
        script = (ROOT / ".github/scripts/release.cjs").read_text()
        self.assertIn("uiPackageAssets", script)
        self.assertIn(".sigstore.json", script)

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
            self.assertEqual(caller["with"], {
                "candidate_sha": "${{ inputs.candidate_sha }}",
                "candidate_ref": "${{ inputs.candidate_ref }}",
            })
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
        steps = {step.get("name"): step for job in ci["jobs"].values() for step in job["steps"]}
        self.assertIs(steps["Gitleaks"]["env"]["GITLEAKS_ENABLE_UPLOAD_ARTIFACT"], False)
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


if __name__ == "__main__":
    unittest.main()
