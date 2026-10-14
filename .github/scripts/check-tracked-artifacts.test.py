"""Exercise the artifact guard against real Git indexes and local generated files."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GUARD = Path(__file__).with_name("check-tracked-artifacts.py").resolve()


class TrackedArtifactsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet")

    def git(self, *args: str) -> None:
        subprocess.run(  # noqa: S603 - fixed Git commands in isolated fixtures
            ["git", *args],  # noqa: S607
            cwd=self.root,
            capture_output=True,
            check=True,
        )

    def write(self, path: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fixture\n")

    def guard(self, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - checked-in guard in isolated fixture
            [sys.executable, str(GUARD)],
            cwd=cwd or self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_rejects_tracked_artifacts_at_root_and_nested_paths(self) -> None:
        paths = [
            ".mypy_cache/3.12/cache.db",
            "src/.pytest_cache/v/cache/nodeids",
            "ui/tools/.ruff_cache/cache",
            "src/__pycache__/module.pyc",
            "example.egg-info/PKG-INFO",
            "nested/build/example.egg-info/SOURCES.txt",
        ]
        for path in paths:
            self.write(path)
        self.git("add", "--", *paths)
        result = self.guard()
        self.assertEqual(result.returncode, 1)
        for path in paths:
            self.assertIn(repr(path), result.stderr)

    def test_allows_untracked_and_ignored_generated_files(self) -> None:
        self.write("src/app.py")
        self.git("add", "--", "src/app.py")
        for path in (
            ".mypy_cache/cache.db",
            "nested/.pytest_cache/nodeids",
            ".ruff_cache/cache",
            "src/__pycache__/app.pyc",
            "example.egg-info/PKG-INFO",
            "untracked.txt",
        ):
            self.write(path)
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        (self.root / ".gitignore").write_text(
            ".mypy_cache/\n.pytest_cache/\n.ruff_cache/\n__pycache__/\n*.egg-info/\n"
        )
        self.git("add", "--", ".gitignore")
        self.assertEqual(self.guard().returncode, 0)

    def test_force_added_ignored_artifact_is_rejected(self) -> None:
        (self.root / ".gitignore").write_text("*.egg-info/\n")
        self.write("build/example.egg-info/PKG-INFO")
        self.git("add", "--force", "--", "build/example.egg-info/PKG-INFO")
        self.assertEqual(self.guard().returncode, 1)

    def test_uses_index_including_staged_deletions(self) -> None:
        path = ".pytest_cache/nodeids"
        self.write(path)
        self.git("add", "--", path)
        # A missing working-tree file remains tracked until its index entry is removed.
        (self.root / path).unlink()
        self.assertEqual(self.guard().returncode, 1)
        self.git("rm", "--cached", "--", path)
        self.write(path)
        self.assertEqual(self.guard().returncode, 0)

    def test_paths_with_spaces_newlines_and_git_quote_characters(self) -> None:
        rejected = 'nested space/line\n"quoted".egg-info/PKG-INFO'
        allowed = 'docs/line\n"quoted".egg-info.md'
        self.write(rejected)
        self.write(allowed)
        self.git("add", "--", rejected, allowed)
        result = self.guard()
        self.assertEqual(result.returncode, 1)
        self.assertIn(repr(rejected), result.stderr)
        self.assertNotIn(repr(allowed), result.stderr)
        self.assertEqual(len(result.stderr.splitlines()), 2)

    def test_allows_similarly_named_source_files_and_directories(self) -> None:
        paths = [
            "docs/.mypy_cache.md",
            "docs/.pytest_cache-example/readme.md",
            "docs/.ruff_cache-guide.txt",
            "docs/__pycache__-guide.md",
            "docs/example.egg-info.md",
            "docs/example.egg-info-sources/readme.md",
        ]
        for path in paths:
            self.write(path)
        self.git("add", "--", *paths)
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_checks_whole_repository_when_invoked_from_subdirectory(self) -> None:
        self.write(".mypy_cache/cache.db")
        self.git("add", "--", ".mypy_cache/cache.db")
        nested = self.root / "src"
        nested.mkdir()
        self.assertEqual(self.guard(nested).returncode, 1)

    def test_fails_closed_outside_a_git_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.guard(Path(directory))
        self.assertEqual(result.returncode, 1)
        self.assertIn("Unable to inspect tracked files", result.stderr)


if __name__ == "__main__":
    unittest.main()
