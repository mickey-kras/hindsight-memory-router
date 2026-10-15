import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

SCRIPT = Path(__file__).with_name("coverage-artifact.py").resolve()
CONFIG_PATHS = (
    "pyproject.toml",
    "build-requirements.txt",
    "requirements.txt",
    "dev-requirements.txt",
    "sonar-project.properties",
    ".github/workflows/ci.yml",
)


class CoverageArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in [*CONFIG_PATHS, "memory_router/app.py", "tests/test_app.py"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("print('source')\n")
        target = self.root / ".github/scripts/coverage-artifact.py"
        target.parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT, target)
        self.git("init", "-q")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.com",
            "commit",
            "-qm",
            "fixture",
        )
        sha = self.git("rev-parse", "HEAD").strip()
        self.env = {
            **os.environ,
            "SOURCE_SHA": sha,
            "GITHUB_SHA": sha,
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
            "PRODUCER_RUN_ATTEMPT": "2",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/publish.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": sha,
            "CANDIDATE_SHA": "",
            "GITHUB_OUTPUT": str(self.root / "outputs"),
            "COVERAGE_ARTIFACT_ID": "456",
        }
        self.xml = (
            f'<coverage lines-valid="1" branches-valid="2"><sources><source>{self.root}/memory_router</source></sources>'
            '<packages><package><classes><class filename="app.py"><lines><line number="1" hits="1"/>'
            "</lines></class></classes></package></packages></coverage>"
        )
        (self.root / "coverage.xml").write_text(self.xml)
        self.artifact = self.root / "artifact"

    def git(self, *args):
        return subprocess.check_output(["/usr/bin/git", *args], cwd=self.root, text=True)  # noqa: S603 - test fixture arguments.

    def run_script(self, mode, **env):
        return subprocess.run(  # noqa: S603 - local fixture and fixed test script.
            [sys.executable, str(SCRIPT), mode, str(self.artifact)],
            cwd=self.root,
            env={**self.env, **env},
            text=True,
            capture_output=True,
            check=False,
        )

    def prepare(self):
        result = self.run_script("prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.root / "coverage.xml").unlink()

    def rewrite_manifest(self, **values):
        path = self.artifact / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest.update(values)
        path.write_text(json.dumps(manifest))

    def test_portable_import_and_same_run_failed_job_retry(self):
        self.prepare()
        tree = ET.parse(self.artifact / "coverage.xml")  # noqa: S314 - locally generated fixture.
        self.assertEqual(tree.findtext("sources/source"), ".")
        self.assertEqual(
            tree.find("packages/package/classes/class").get("filename"), "memory_router/app.py"
        )
        result = self.run_script("restore", GITHUB_RUN_ATTEMPT="3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.root / "coverage.xml").read_bytes(), (self.artifact / "coverage.xml").read_bytes()
        )
        self.assertIn("config_sha256=", (self.root / "outputs").read_text())

    def test_producer_rejects_pr_candidate_wrong_checkout_and_attempt(self):
        for env in [
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"CANDIDATE_SHA": "a" * 40},
            {"GITHUB_REF": "refs/heads/feat/example"},
            {"SOURCE_SHA": "a" * 40},
            {"SOURCE_SHA": "a" * 40, "GITHUB_SHA": "a" * 40},
            {"PRODUCER_RUN_ATTEMPT": "1"},
        ]:
            with self.subTest(env=env):
                self.assertNotEqual(self.run_script("prepare", **env).returncode, 0)
                self.assertFalse(self.artifact.exists())

    def test_consumer_rejects_missing_id_and_mismatched_context(self):
        self.prepare()
        for env in [
            {"COVERAGE_ARTIFACT_ID": ""},
            {"COVERAGE_ARTIFACT_ID": "456,789"},
            {"SOURCE_SHA": "a" * 40},
            {"SOURCE_SHA": "a" * 40, "GITHUB_SHA": "a" * 40},
            {"GITHUB_RUN_ID": "124"},
            {"PRODUCER_RUN_ATTEMPT": "1"},
            {"GITHUB_RUN_ATTEMPT": "1"},
            {"GITHUB_REPOSITORY": "fork/repo"},
            {"GITHUB_WORKFLOW_SHA": "b" * 40},
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"CANDIDATE_SHA": "a" * 40},
            {"GITHUB_REF": "refs/heads/release/1.0.0"},
        ]:
            with self.subTest(env=env):
                self.assertNotEqual(self.run_script("restore", **env).returncode, 0)
                self.assertFalse((self.root / "coverage.xml").exists())

    def test_producer_rejects_modified_or_untracked_source(self):
        (self.root / "memory_router/app.py").write_text("changed source\n")
        self.assertNotEqual(self.run_script("prepare").returncode, 0)
        self.git("restore", "memory_router/app.py")
        (self.root / "memory_router/untracked.py").write_text("untracked source\n")
        self.assertNotEqual(self.run_script("prepare").returncode, 0)
        self.assertFalse(self.artifact.exists())
        (self.root / "memory_router/untracked.py").unlink()
        (self.root / ".gitignore").write_text("memory_router/ignored.py\n")
        (self.root / "memory_router/ignored.py").write_text("ignored source\n")
        (self.root / "coverage.xml").write_text(self.xml.replace("app.py", "ignored.py"))
        result = self.run_script("prepare")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a tracked source", result.stderr)

    def test_producer_rejects_dirty_lock_and_coverage_configuration(self):
        for name in CONFIG_PATHS:
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed configuration\n")
                result = self.run_script("prepare")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("configuration differs from checkout", result.stderr)
                self.assertFalse(self.artifact.exists())
                path.write_bytes(original)

    def test_consumer_rejects_changed_config_even_when_committed(self):
        self.prepare()
        (self.root / "build-requirements.txt").write_text("changed build backend\n")
        self.git("add", "build-requirements.txt")
        self.git(
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.com",
            "commit",
            "-qm",
            "changed",
        )
        sha = self.git("rev-parse", "HEAD").strip()
        manifest = json.loads((self.artifact / "manifest.json").read_text())
        manifest["producer"].update(sha=sha, workflow_sha=sha)
        self.rewrite_manifest(producer=manifest["producer"])
        result = self.run_script("restore", SOURCE_SHA=sha, GITHUB_SHA=sha, GITHUB_WORKFLOW_SHA=sha)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configuration mismatch", result.stderr)

    def test_missing_empty_corrupt_xml_and_manifest_fail_closed(self):
        self.prepare()
        original_xml = (self.artifact / "coverage.xml").read_bytes()
        for data in [b"", b"broken XML", original_xml + b"tampered"]:
            with self.subTest(data=data[:20]):
                (self.artifact / "coverage.xml").write_bytes(data)
                self.assertNotEqual(self.run_script("restore").returncode, 0)
        (self.artifact / "coverage.xml").write_bytes(original_xml)
        (self.artifact / "manifest.json").unlink()
        self.assertNotEqual(self.run_script("restore").returncode, 0)
        (self.artifact / "manifest.json").write_text("{broken")
        self.assertNotEqual(self.run_script("restore").returncode, 0)
        self.assertFalse((self.root / "coverage.xml").exists())

    def test_well_formed_measurement_tampering_fails_checksum(self):
        self.prepare()
        path = self.artifact / "coverage.xml"
        original = path.read_text()
        changed = original.replace('hits="1"', 'hits="0"')
        self.assertNotEqual(changed, original)
        path.write_text(changed)
        result = self.run_script("restore")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coverage XML checksum mismatch", result.stderr)
        self.assertFalse((self.root / "coverage.xml").exists())

    def test_producer_rejects_empty_malformed_and_entity_xml(self):
        for data in [
            b"",
            b"<not-coverage/>",
            b"broken XML",
            b'<!DOCTYPE coverage [<!ENTITY x "entity">]><coverage>&x;</coverage>',
            self.xml.encode("utf-16"),
        ]:
            with self.subTest(data=data[:20]):
                (self.root / "coverage.xml").write_bytes(data)
                self.assertNotEqual(self.run_script("prepare").returncode, 0)
                self.assertFalse(self.artifact.exists())

    def test_checksum_valid_xml_still_requires_measured_portable_sources(self):
        self.prepare()
        original = (self.artifact / "coverage.xml").read_text()
        for changed in [
            original.replace("memory_router/app.py", "../app.py"),
            original.replace("memory_router/app.py", "tests/test_app.py"),
            original.replace("memory_router/app.py", "memory_router/missing.py"),
            original.replace("<source>.</source>", "<source>/old/checkout</source>"),
            original.replace('lines-valid="1"', 'lines-valid="0"'),
            original.replace('lines-valid="1"', 'lines-valid="NaN"'),
            original.replace('branches-valid="2"', 'branches-valid="0"'),
            original.replace('<line number="1" hits="1" />', ""),
        ]:
            with self.subTest(changed=changed):
                data = changed.encode()
                (self.artifact / "coverage.xml").write_bytes(data)
                self.rewrite_manifest(xml_sha256=hashlib.sha256(data).hexdigest())
                self.assertNotEqual(self.run_script("restore").returncode, 0)
                self.assertFalse((self.root / "coverage.xml").exists())


if __name__ == "__main__":
    unittest.main()
