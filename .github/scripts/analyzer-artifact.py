"""Transfer analyzer reports from a successful main CI job to the matching Sonar scan."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

PAYLOADS = {
    "python": ("reports/ruff.json", "reports/mypy.txt"),
    "ui": ("reports/eslint.json", "ui/coverage/lcov.info"),
}


def transfer(mode: str, kind: str, directory: Path) -> None:
    keys = ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_EVENT_NAME", "GITHUB_REF")
    context = {key: os.environ[key] for key in keys}
    attempt = os.environ["PRODUCER_RUN_ATTEMPT"]
    if (
        context["GITHUB_EVENT_NAME"] not in {"push", "workflow_dispatch"}
        or context["GITHUB_REF"] != "refs/heads/main"
        or not re.fullmatch(r"[0-9a-f]{40}", context["GITHUB_SHA"])
        or not re.fullmatch(r"[1-9][0-9]*", context["GITHUB_RUN_ID"])
        or not re.fullmatch(r"[1-9][0-9]*", attempt)
        or attempt != os.environ["GITHUB_RUN_ATTEMPT"]
        or os.environ.get("CANDIDATE_SHA")
    ):
        raise ValueError("analyzer evidence must come from the matching main run")
    head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], text=True).strip()
    if head != context["GITHUB_SHA"]:
        raise ValueError("analyzer checkout differs from main run")
    changes = subprocess.check_output(  # noqa: S603 - fixed executable and source paths.
        [
            "/usr/bin/git",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "memory_router",
            "ui/src",
            "ui/tests/unit",
            "ui/package.json",
            "ui/package-lock.json",
            "ui/tsconfig.json",
            "ui/eslint.config.mjs",
            "ui/vitest.config.ts",
            "pyproject.toml",
            "dev-requirements.txt",
            "requirements.txt",
            "sonar-project.properties",
            ".github/scripts/analyzer-artifact.py",
            ".github/workflows/ci.yml",
        ],
        text=True,
    )
    if changes:
        raise ValueError("analyzer sources or configuration differ from checkout")
    context["producer_attempt"] = attempt
    names = PAYLOADS[kind]
    if mode == "prepare":
        if attempt != os.environ["GITHUB_RUN_ATTEMPT"]:
            raise ValueError("producer attempt differs from current attempt")
        directory.mkdir(parents=True, exist_ok=False)
        hashes: dict[str, str] = {}
        for name in names:
            source = Path(name)
            data = source.read_bytes()
            if name.endswith(".json"):
                diagnostics = json.loads(data)
                if not isinstance(diagnostics, list):
                    raise ValueError("analyzer JSON must be a diagnostics array")
                field = "filePath" if kind == "ui" else "filename"
                for diagnostic in diagnostics:
                    path = Path(diagnostic[field])
                    if path.is_absolute():
                        diagnostic[field] = path.relative_to(Path.cwd()).as_posix()
                    elif ".." in path.parts:
                        raise ValueError("analyzer diagnostic is outside the checkout")
                data = (json.dumps(diagnostics) + "\n").encode()
            if name.endswith(".info"):
                if b"SF:src/" not in data:
                    raise ValueError("UI coverage contains no source files")
                data = data.replace(b"SF:src/", b"SF:ui/src/")
            hashes[name] = hashlib.sha256(data).hexdigest()
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (directory / "manifest.json").write_text(
            json.dumps({"producer": context, "kind": kind, "files": hashes}, sort_keys=True) + "\n"
        )
    else:
        manifest = json.loads((directory / "manifest.json").read_text())
        if manifest.get("producer") != context or manifest.get("kind") != kind:
            raise ValueError("analyzer producer does not match current scan")
        hashes = manifest.get("files", {})
        if set(hashes) != set(names):
            raise ValueError("analyzer bundle is incomplete")
        for name in names:
            source = directory / name
            if (
                source.is_symlink()
                or hashlib.sha256(source.read_bytes()).hexdigest() != hashes[name]
            ):
                raise ValueError("analyzer report checksum mismatch")
        for name in names:
            target = Path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(directory / name, target)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "restore"))
    parser.add_argument("kind", choices=PAYLOADS)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    transfer(args.mode, args.kind, args.directory)


if __name__ == "__main__":
    main()
