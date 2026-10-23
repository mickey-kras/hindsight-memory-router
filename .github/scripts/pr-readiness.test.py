"""Draft feedback must never stand in for ready PR validation."""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path.cwd()
spec = importlib.util.spec_from_file_location("release_policy", ROOT / ".github/scripts/release-policy.test.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ReadinessTests(unittest.TestCase):
    def test_lifecycle_events_and_full_callers(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr-validation.yml").read_text())
        events = workflow.get("on", workflow.get(True))["pull_request"]["types"]
        self.assertEqual(set(events), {"opened", "synchronize", "reopened", "ready_for_review", "converted_to_draft", "edited"})
        jobs = workflow["jobs"]
        self.assertNotIn("if", jobs["quality"])
        for name in ["aislop", "codeql", "architecture"]:
            self.assertEqual(jobs[name]["if"], "github.event.pull_request.draft != true")
        for name in ["branch-policy", "dependency-review", "dependabot-policy"]:
            self.assertNotIn("if", jobs[name])
        self.assertEqual(jobs["draft-feedback"]["permissions"], {"contents": "read"})
        self.assertEqual(jobs["draft-feedback"]["if"], "github.event.pull_request.draft == true")
        self.assertEqual(workflow["concurrency"]["group"], "pr-validation-${{ github.event.pull_request.number }}")
        self.assertIs(workflow["concurrency"]["cancel-in-progress"], True)

    def test_readiness_policy_rejects_unreviewed_changes(self):
        self.assertEqual(policy.policy(), [])
        for path in [".github/workflows/pr-validation.yml", ".github/scripts/pr-readiness.test.py"]:
            self.assertIn(path, policy.PATHS)
            self.assertTrue(policy.policy({path: (ROOT / path).read_text() + "\n# unreviewed change\n"}))

    def test_expensive_jobs_defer_only_ordinary_drafts(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        for name in ["hindsight", "python", "ui", "release", "security", "container"]:
            expression = jobs[name]["if"]
            for event, draft, candidate in [
                ("pull_request", True, ""), ("pull_request", False, ""),
                ("pull_request", True, "a" * 40), ("push", False, ""),
                ("workflow_dispatch", False, "a" * 40),
            ]:
                driver = "const [condition,event,draft,candidate] = JSON.parse(process.argv[1]); " \
                    "console.log(new Function('github','inputs','return ('+condition+');')" \
                    "({event_name:event,event:{pull_request:{draft}}},{candidate_sha:candidate,candidate_ref:''}));"
                result = subprocess.run(["node", "-e", driver, json.dumps([
                    expression, event, draft, candidate,
                ])], text=True, capture_output=True, check=True)
                runs = result.stdout.strip() == "true"
                expected = event == "pull_request" if name == "container" else True
                if event == "pull_request" and draft and not candidate:
                    expected = False
                self.assertEqual(runs, expected, (name, event, draft, candidate))

    def test_draft_success_is_not_merge_success(self):
        needs = policy.successful_quality_needs()
        self.assertTrue(policy.quality_gate(needs, draft="true"))
        self.assertEqual(policy.quality_gate(needs, draft="false"), [])
        for event in ["push", "workflow_dispatch"]:
            needs["container"]["result"] = "skipped"
            needs["docs-ste"]["result"] = "skipped"
            self.assertEqual(policy.quality_gate(needs, event=event, draft="true"), [])

    def test_full_gate_remains_fail_closed_after_readiness(self):
        passing = policy.successful_quality_needs()
        for name in passing:
            for result in ["skipped", "failure", "cancelled", "neutral", None]:
                self.assertTrue(policy.quality_gate({**passing, name: {"result": result}}))
            self.assertTrue(policy.quality_gate({key: value for key, value in passing.items() if key != name}))

    def test_live_gate_rejects_stale_same_sha_events_and_api_failure(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        step = jobs["checks"]["steps"][1]
        self.assertEqual(step["if"], "github.event_name == 'pull_request'")
        expected = {"number": 1, "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}}
        ready = {**expected, "state": "open", "draft": False}
        driver = r"""
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const failures = [];
const github = {rest: {pulls: {get: async () => {
  if (input.unavailable) throw new Error('metadata unavailable');
  return {data: input.current};
}}}};
const context = {repo: {owner: 'test', repo: 'test'}, payload: {pull_request: input.expected}};
const core = {setFailed: message => failures.push(message)};
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
new AsyncFunction('github', 'context', 'core', input.script)(github, context, core)
  .then(() => process.stdout.write(JSON.stringify(failures)))
  .catch(() => process.exit(1));
"""
        for current, unavailable, fails, fresh_base in [
            (ready, False, False, False),
            ({**ready, "draft": True}, False, True, False),
            ({**ready, "draft": None}, False, True, False),
            ({**ready, "state": "closed"}, False, True, False),
            ({**ready, "head": {"sha": "c" * 40}}, False, True, False),
            ({**ready, "base": {"sha": "c" * 40}}, False, True, False),
            (ready, True, True, False),
            # An edited/base event must validate the fresh target, not the old payload.
            ({**ready, "base": {"sha": "c" * 40}}, False, False, True),
        ]:
            result = subprocess.run(["node", "-e", driver], input=json.dumps({
                "script": step["with"]["script"], "current": current,
                "expected": {**expected, "base": {"sha": "c" * 40}} if fresh_base else expected,
                "unavailable": unavailable,
            }), text=True, capture_output=True, check=False)
            rejected = result.returncode != 0 or bool(json.loads(result.stdout))
            self.assertEqual(rejected, fails)


if __name__ == "__main__":
    unittest.main()
