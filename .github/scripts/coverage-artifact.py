"""Bind authoritative CI coverage to its trusted producer and portable source paths."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

CONFIG_PATHS = (
    "pyproject.toml",
    "build-requirements.txt",
    "requirements.txt",
    "dev-requirements.txt",
    "sonar-project.properties",
    ".github/workflows/ci.yml",
    ".github/scripts/coverage-artifact.py",
)
CONTEXT_ENV = {
    "sha": "SOURCE_SHA",
    "repository": "GITHUB_REPOSITORY",
    "run_id": "GITHUB_RUN_ID",
    "run_attempt": "PRODUCER_RUN_ATTEMPT",
    "event": "GITHUB_EVENT_NAME",
    "ref": "GITHUB_REF",
    "workflow_ref": "GITHUB_WORKFLOW_REF",
    "workflow_sha": "GITHUB_WORKFLOW_SHA",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def context() -> dict[str, str]:
    values = {key: os.environ.get(env, "") for key, env in CONTEXT_ENV.items()}
    require(all(values.values()), "missing producer context")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", values["sha"])), "invalid source SHA")
    require(values["event"] in {"push", "workflow_dispatch"}, "untrusted event")
    require(values["ref"] == "refs/heads/main", "untrusted ref")
    require(not os.environ.get("CANDIDATE_SHA"), "candidate coverage is not trusted main evidence")
    require(values["sha"] == os.environ.get("GITHUB_SHA"), "source differs from main run SHA")
    for key in ["run_id", "run_attempt"]:
        require(bool(re.fullmatch(r"[1-9][0-9]*", values[key])), "invalid producer run identity")
    current_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(bool(re.fullmatch(r"[1-9][0-9]*", current_attempt)), "invalid current run attempt")
    require(
        int(values["run_attempt"]) <= int(current_attempt), "producer attempt exceeds current run"
    )
    head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], text=True).strip()
    require(head == values["sha"], "checkout differs from producer source SHA")
    changes = subprocess.check_output(  # noqa: S603 - fixed executable and repository paths.
        [
            "/usr/bin/git",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "memory_router",
            "tests",
            *CONFIG_PATHS,
        ],
        text=True,
    )
    require(not changes, "coverage source or configuration differs from checkout")
    return values


def config_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for name in CONFIG_PATHS:
        digest.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    return digest.hexdigest()


def xml_tree(data: bytes) -> ET.Element:
    require(0 < len(data) <= 20_000_000, "coverage XML is empty or oversized")
    require(b"\0" not in data, "coverage XML has unsupported encoding")
    require(b"<!ENTITY" not in data.upper(), "coverage XML contains entities")
    try:
        tree = ET.fromstring(data)  # noqa: S314 - bounded trusted-run XML; entities rejected above.
    except ET.ParseError:
        raise ValueError("coverage XML is malformed") from None
    require(tree.tag == "coverage", "coverage XML has unexpected root")
    for key in ["lines-valid", "branches-valid"]:
        require(
            bool(re.fullmatch(r"[1-9][0-9]*", tree.get(key, ""))), "coverage counters are empty"
        )
    require(
        bool(tree.findall("./packages/package/classes/class/lines/line")),
        "coverage XML contains no measured lines",
    )
    return tree


def source_paths(tree: ET.Element, root: Path, *, normalize: bool) -> None:
    sources = tree.find("sources")
    if sources is None or not list(sources):
        raise ValueError("coverage XML has no source paths")
    if not normalize:
        require([item.text for item in sources] == ["."], "coverage source paths are not portable")
    router = (root / "memory_router").resolve()
    tracked = set(
        subprocess.check_output(
            ["/usr/bin/git", "ls-files", "-z", "--", "memory_router"], cwd=root, text=True
        ).split("\0")
    )
    seen: set[str] = set()
    for item in tree.findall("./packages/package/classes/class"):
        filename = item.get("filename", "")
        require(
            bool(filename)
            and not Path(filename).is_absolute()
            and ".." not in Path(filename).parts,
            "invalid coverage filename",
        )
        if normalize:
            matches = {
                (root / (source.text or "") / filename).resolve()
                for source in sources
                if (root / (source.text or "") / filename).is_file()
            }
            require(len(matches) == 1, "coverage source attribution is missing or ambiguous")
            path = matches.pop()
        else:
            path = (root / filename).resolve()
        require(
            path.is_relative_to(router) and path.suffix == ".py" and path.is_file(),
            "coverage filename is outside checked-out Python sources",
        )
        relative = path.relative_to(root).as_posix()
        require(relative in tracked, "coverage filename is not a tracked source")
        require(relative not in seen, "duplicate coverage source attribution")
        seen.add(relative)
        if normalize:
            item.set("filename", relative)
        else:
            require(filename == relative, "coverage filename is not portable")
    require(bool(seen), "coverage XML contains no attributed sources")
    if normalize:
        sources.clear()
        ET.SubElement(sources, "source").text = "."


def prepare(directory: Path, root: Path) -> None:
    values = context()
    require(
        values["run_attempt"] == os.environ["GITHUB_RUN_ATTEMPT"],
        "producer attempt differs from current run",
    )
    tree = xml_tree((root / "coverage.xml").read_bytes())
    source_paths(tree, root, normalize=True)
    directory.mkdir(parents=True, exist_ok=False)
    ET.ElementTree(tree).write(directory / "coverage.xml", encoding="utf-8", xml_declaration=True)
    digest = config_digest(root)
    manifest = {
        "schema": 1,
        "producer": values,
        "config_sha256": digest,
        "xml_sha256": hashlib.sha256((directory / "coverage.xml").read_bytes()).hexdigest(),
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"config_sha256={digest}\nrun_attempt={values['run_attempt']}\n")


def restore(directory: Path, root: Path) -> None:
    values = context()
    require(
        bool(re.fullmatch(r"[1-9][0-9]*", os.environ.get("COVERAGE_ARTIFACT_ID", ""))),
        "missing authoritative coverage artifact ID",
    )
    require(
        (directory / "manifest.json").stat().st_size <= 10_000, "coverage manifest is oversized"
    )
    try:
        manifest = json.loads((directory / "manifest.json").read_text())
    except (json.JSONDecodeError, UnicodeError):
        raise ValueError("coverage manifest is malformed") from None
    require(
        isinstance(manifest, dict) and manifest.get("schema") == 1, "unsupported coverage manifest"
    )
    require(manifest.get("producer") == values, "coverage producer context mismatch")
    require(manifest.get("config_sha256") == config_digest(root), "coverage configuration mismatch")
    data = (directory / "coverage.xml").read_bytes()
    require(
        manifest.get("xml_sha256") == hashlib.sha256(data).hexdigest(),
        "coverage XML checksum mismatch",
    )
    tree = xml_tree(data)
    source_paths(tree, root, normalize=False)
    (root / "coverage.xml").write_bytes(data)
    print("Verified authoritative coverage XML and checked-out source attribution.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["prepare", "restore"])
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        {"prepare": prepare, "restore": restore}[args.mode](args.directory, Path.cwd().resolve())
    except (OSError, subprocess.SubprocessError):
        print(
            "CoverageEvidenceError: evidence is missing or unreadable; rerun authoritative main CI.",
            file=sys.stderr,
        )
        return 1
    except ValueError as error:
        print(f"CoverageEvidenceError: {error}; rerun authoritative main CI.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
