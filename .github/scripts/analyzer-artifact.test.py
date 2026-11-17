"""Reject analyzer reports from a different run or altered payload."""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "analyzer_artifact", Path(__file__).with_name("analyzer-artifact.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load analyzer artifact helper")
ARTIFACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACT)


class AnalyzerArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.addCleanup(os.chdir, Path.cwd())
        os.chdir(self.root)
        subprocess.run(["/usr/bin/git", "init", "-q"], check=True)
        subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "--allow-empty",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        sha = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], text=True).strip()
        environment = {
            "GITHUB_REPOSITORY": "owner/router",
            "GITHUB_SHA": sha,
            "GITHUB_RUN_ID": "123",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ATTEMPT": "1",
            "PRODUCER_RUN_ATTEMPT": "1",
            "ANALYZER_ARTIFACT_ID": "456",
            "CANDIDATE_SHA": "",
        }
        patcher = patch.dict(os.environ, environment)
        patcher.start()
        self.addCleanup(patcher.stop)
        Path("reports").mkdir()
        Path("reports/ruff.json").write_text("[]")
        Path("reports/mypy.txt").write_text("")
        self.bundle = self.root / "bundle"

    def test_empty_successful_reports_are_restored(self):
        ARTIFACT.transfer("prepare", "python", self.bundle)
        Path("reports/mypy.txt").unlink()
        ARTIFACT.transfer("restore", "python", self.bundle)
        self.assertEqual(Path("reports/mypy.txt").read_text(), "")

    def test_diagnostic_paths_are_portable(self):
        Path("reports/ruff.json").write_text(
            json.dumps([{"filename": str(self.root / "memory_router/app.py")}])
        )
        ARTIFACT.transfer("prepare", "python", self.bundle)
        self.assertEqual(
            json.loads((self.bundle / "reports/ruff.json").read_text())[0]["filename"],
            "memory_router/app.py",
        )

    def test_old_attempt_requires_rerunning_all_jobs(self):
        ARTIFACT.transfer("prepare", "python", self.bundle)
        os.environ["GITHUB_RUN_ATTEMPT"] = "2"
        with self.assertRaisesRegex(ValueError, "main run"):
            ARTIFACT.transfer("restore", "python", self.bundle)

    def test_wrong_run_is_rejected(self):
        ARTIFACT.transfer("prepare", "python", self.bundle)
        os.environ["GITHUB_RUN_ID"] = "789"
        with self.assertRaisesRegex(ValueError, "producer"):
            ARTIFACT.transfer("restore", "python", self.bundle)

    def test_altered_payload_is_rejected(self):
        ARTIFACT.transfer("prepare", "python", self.bundle)
        (self.bundle / "reports/ruff.json").write_text("[{}]")
        with self.assertRaisesRegex(ValueError, "checksum"):
            ARTIFACT.transfer("restore", "python", self.bundle)

    def test_missing_report_is_rejected(self):
        Path("reports/mypy.txt").unlink()
        with self.assertRaises(FileNotFoundError):
            ARTIFACT.transfer("prepare", "python", self.bundle)

    def test_modified_source_is_rejected(self):
        Path("ui/src").mkdir(parents=True)
        Path("ui/src/changed.ts").write_text("export const changed = true;")
        with self.assertRaisesRegex(ValueError, "sources or configuration"):
            ARTIFACT.transfer("prepare", "python", self.bundle)

    def test_ui_coverage_and_eslint_paths_are_portable(self):
        Path("reports/eslint.json").write_text(
            json.dumps([{"filePath": str(self.root / "ui/src/App.tsx")}])
        )
        Path("ui/coverage").mkdir(parents=True)
        Path("ui/coverage/lcov.info").write_text("SF:src/App.tsx\nDA:1,1\nend_of_record\n")
        ARTIFACT.transfer("prepare", "ui", self.bundle)
        self.assertIn("SF:ui/src/App.tsx", (self.bundle / "ui/coverage/lcov.info").read_text())
        self.assertEqual(
            json.loads((self.bundle / "reports/eslint.json").read_text())[0]["filePath"],
            "ui/src/App.tsx",
        )

    def test_pr_evidence_is_rejected(self):
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        with self.assertRaisesRegex(ValueError, "main run"):
            ARTIFACT.transfer("prepare", "python", self.bundle)


if __name__ == "__main__":
    unittest.main()
