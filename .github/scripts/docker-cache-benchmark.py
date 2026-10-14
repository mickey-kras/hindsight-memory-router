"""Temporary hosted benchmark for issue 511; never builds the gate image."""

import hashlib
import io
import json
import os
import re
import statistics
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path


ROOT = Path.cwd()
OUTPUT = Path(os.environ["RUNNER_TEMP"]) / "docker-cache-benchmark"
OUTPUT.mkdir(exist_ok=True)
SECRETS = [os.environ.get(name, "") for name in ["ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL", "CACHE_GITHUB_TOKEN"]]


def redact(text):
    for value in SECRETS:
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def command(args, *, log=None, timing=None):
    started = time.monotonic()
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    finally:
        if timing is not None:
            timing["seconds"] = round(time.monotonic() - started, 3)
    output = redact(result.stdout)
    if log:
        log.write_text(output)
        print(output, flush=True)
    if result.returncode:
        raise RuntimeError(f"{args[0]} command failed with exit {result.returncode}: {output[-4000:]}")
    return output.strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stages(log):
    result = {}
    for line in log.splitlines():
        match = re.match(r"^#(\d+) \[(builder|runtime) [^\]]+\] (.*)$", line)
        if match:
            number, stage, instruction = match.groups()
            result.setdefault(number, {"stage": stage, "instruction": instruction, "cached": False, "done": False, "materialized": False, "output": []})
        status = re.match(r"^#(\d+) (CACHED|DONE)(?: |$)", line)
        if status and status[1] in result:
            result[status[1]]["cached" if status[2] == "CACHED" else "done"] = True
        extraction = re.match(r"^#(\d+) extracting sha256:[a-f0-9]{64}.*\bdone$", line)
        if extraction and extraction[1] in result:
            result[extraction[1]]["materialized"] = True
        output = re.match(r"^#(\d+) [0-9.]+ (.*)$", line)
        if output and output[1] in result:
            result[output[1]]["output"].append(output[2])
    return list(result.values())


def instruction(records, stage, text):
    matching = [record for record in records if record["stage"] == stage and text in record["instruction"]]
    if len(matching) != 1:
        raise AssertionError(f"Expected one {stage} instruction containing {text}: {matching}")
    return matching[0]


def verify_log(records, kind):
    def reused(record):
        return (record["cached"] or (record["done"] and record["materialized"])) and not record["output"]

    def executed(record, message):
        return record["done"] and not record["cached"] and any(message in line for line in record["output"])

    apk = instruction(records, "runtime", "apk upgrade --no-cache")
    assert executed(apk, "OK:"), "Runtime APK update was not executed"
    dependencies = instruction(records, "builder", "-r build-requirements.txt")
    wheel = instruction(records, "builder", "--wheel-dir /wheels")
    if kind in {"warm", "requirements", "candidate"}:
        assert reused(dependencies) and reused(wheel), "Expected restored builder cache"
    elif kind in {"dockerfile", "source"}:
        assert reused(dependencies) and executed(wheel, "Successfully built hindsight-memory-router"), "Changed wheel source did not invalidate"
    else:
        assert executed(dependencies, "Successfully installed setuptools-"), "Expected backend install cache miss"
        assert executed(wheel, "Successfully built hindsight-memory-router"), "Expected wheel cache miss"
    runtime_install = instruction(records, "runtime", "--require-hashes -r requirements.txt")
    assert executed(runtime_install, "Successfully installed "), "Runtime dependencies were not installed afresh"


def measure(name, kind, archive, scope, head, samples):
    builder = f"cache-bench-{os.environ['GITHUB_RUN_ID']}-{name}"
    tag = f"hindsight-cache-benchmark:{name}"
    marker = f'\nHMR_CACHE_BENCHMARK = "{kind}"\n'
    with tempfile.TemporaryDirectory(prefix="docker-cache-context-") as temporary:
        context = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
            tree.extractall(context, filter="data")
        module = context / "memory_router/__init__.py"
        expected_module = module.read_bytes()
        if kind == "source":
            module.write_text(module.read_text() + marker)
            expected_module = module.read_bytes()
        elif kind == "dockerfile":
            dockerfile = context / "Dockerfile"
            addition = "RUN printf '%s\\n' '' 'HMR_CACHE_BENCHMARK = \"dockerfile\"' >> memory_router/__init__.py\n"
            dockerfile.write_text(dockerfile.read_text().replace("RUN --network=none python -m pip wheel", addition + "RUN --network=none python -m pip wheel", 1))
            expected_module += marker.encode()
        elif kind in {"requirements", "build-requirements"}:
            path = context / (kind + ".txt")
            path.write_text(path.read_text() + f"\n# Cache invalidation fixture: {kind}\n")

        inputs = {path: digest(context / path) for path in ["Dockerfile", "build-requirements.txt", "requirements.txt", "memory_router/__init__.py"]}
        command(["docker", "buildx", "create", "--name", builder, "--driver", "docker-container"])
        image_created = False
        try:
            bootstrap = command(["docker", "buildx", "inspect", "--builder", builder, "--bootstrap"])
            (OUTPUT / f"{name}-builder.txt").write_text(bootstrap + "\n")
            buildkit = re.search(r"BuildKit version:\s*(\S+)", bootstrap)
            args = ["docker", "buildx", "build", "--builder", builder, "--load", "--provenance=false", "--no-cache-filter", "runtime", "--progress=plain", "--tag", tag,
                    "--label", f"org.opencontainers.image.revision={head}", "--label", f"io.hmr.cache-benchmark.sample={name}"]
            if kind != "baseline":
                args += ["--cache-from", f"type=gha,version=2,scope={scope},timeout=30s"]
                if kind != "candidate":
                    destination = scope if kind in {"cold", "warm"} else f"{scope}-{kind}"
                    args += ["--cache-to", f"type=gha,version=2,scope={destination},mode=max,timeout=30s,repository={os.environ['GITHUB_REPOSITORY']},ghtoken={os.environ['CACHE_GITHUB_TOKEN']}"]
            args.append(str(context))
            sample = {"name": name, "kind": kind, "inputs": inputs, "verified": False, "buildkit_version": buildkit[1] if buildkit else None}
            samples.append(sample)
            try:
                log = command(args, log=OUTPUT / f"{name}.log", timing=sample)
            finally:
                (OUTPUT / "samples.json").write_text(json.dumps(samples, indent=2) + "\n")
            image_created = True
            image = json.loads(command(["docker", "image", "inspect", tag]))[0]
            sample["image_id"] = image["Id"]
            records = stages(log)
            sample["steps"] = records
            if re.search(r"(?im)^.*(?:ERROR|WARNING).*cache|failed to (?:import|export|configure).*cache", log):
                raise AssertionError("Cache reported an error; sample cannot prove caching")
            verify_log(records, kind)
            if kind != "baseline":
                assert "importing cache manifest from gha:" in log, "GHA import was not attempted"
                if kind != "candidate":
                    assert "exporting to GitHub Actions Cache" in log, "GHA export was not attempted"
            assert image["Config"]["Labels"]["org.opencontainers.image.revision"] == head
            expected = {"module": hashlib.sha256(expected_module).hexdigest(), "requirements": inputs["requirements.txt"]}
            actual = json.loads(command(["docker", "run", "--rm", "--network", "none", "--entrypoint", "python", tag, "-I", "-c",
                                        "import hashlib,json,pathlib,memory_router; print(json.dumps({'module':hashlib.sha256(pathlib.Path(memory_router.__file__).read_bytes()).hexdigest(),'requirements':hashlib.sha256(pathlib.Path('/app/requirements.txt').read_bytes()).hexdigest()}))"]))
            assert actual == expected, (name, actual, expected)
            sample.update({"image_contents": actual, "verified": True})
            (OUTPUT / "samples.json").write_text(json.dumps(samples, indent=2) + "\n")
            print(json.dumps({key: sample[key] for key in ["name", "kind", "seconds", "image_id"]}), flush=True)
        finally:
            command(["docker", "buildx", "rm", builder])
            if image_created:
                command(["docker", "image", "rm", "--force", tag])


def main():
    for name in ["ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL", "CACHE_GITHUB_TOKEN", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY", "SOURCE_IMAGE", "BENCHMARK_GATE_IMAGE_ID", "BENCHMARK_SOURCE_SHA"]:
        if not os.environ.get(name):
            raise RuntimeError(f"Missing {name}; run this fixture as a child of github-script")
    head = command(["git", "rev-parse", "HEAD"])
    source_before = command(["docker", "image", "inspect", os.environ["SOURCE_IMAGE"], "--format", "{{.Id}}"])
    assert source_before == os.environ["BENCHMARK_GATE_IMAGE_ID"], "Image changed after uncached fallback validation"
    assert head == os.environ["BENCHMARK_SOURCE_SHA"], "Fallback built from a different checkout"
    status_before = command(["git", "status", "--porcelain", "--untracked-files=no"])
    scope = f"router-benchmark-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    archive = subprocess.run(["git", "archive", "HEAD"], stdout=subprocess.PIPE, check=True).stdout
    samples = []
    metadata = {"head": head, "scope": scope, "source_image": os.environ["SOURCE_IMAGE"], "source_image_id": source_before,
                "tree": command(["git", "rev-parse", "HEAD^{tree}"]), "repository": os.environ["GITHUB_REPOSITORY"],
                "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                "timing": "buildx subprocess wall time including cache import/export and image load; excludes builder bootstrap and log processing",
                "limitations": ["Fresh builders share one runner host and network", "GHA cache is created and restored within one run",
                                "Candidate-style sample uses CLI import-only behavior, not the release workflow",
                                "Dependency fixtures change comments, not dependency versions; runtime requirements always install afresh",
                                "Image content checks cover selected module and requirements bytes; ordinary workflow gates validate the source image"],
                "docker": command(["docker", "version"]), "buildx": command(["docker", "buildx", "version"]), "samples": samples}
    try:
        sequence = [("baseline-1", "baseline"), ("cold", "cold"), ("warm-1", "warm"), ("baseline-2", "baseline"),
                    ("warm-2", "warm"), ("baseline-3", "baseline"), ("warm-3", "warm"), ("candidate-warm", "candidate"),
                    ("dockerfile", "dockerfile"), ("requirements", "requirements"), ("build-requirements", "build-requirements"), ("source", "source")]
        for name, kind in sequence:
            measure(name, kind, archive, scope, head, samples)
        assert len(samples) == len(sequence) == 12 and all(sample["verified"] for sample in samples), "Incomplete verified sample set"
        baseline = statistics.median(sample["seconds"] for sample in samples if sample["kind"] == "baseline")
        warm = statistics.median(sample["seconds"] for sample in samples if sample["kind"] == "warm")
        metadata["comparison"] = {"baseline_median_seconds": baseline, "warm_median_seconds": warm, "net_saving_seconds": round(baseline - warm, 3)}
        print(json.dumps(metadata["comparison"]), flush=True)
    finally:
        metadata["source_image_id_after"] = command(["docker", "image", "inspect", os.environ["SOURCE_IMAGE"], "--format", "{{.Id}}"])
        metadata["head_after"] = command(["git", "rev-parse", "HEAD"])
        metadata["tracked_status_unchanged"] = status_before == command(["git", "status", "--porcelain", "--untracked-files=no"])
        (OUTPUT / "results.json").write_text(json.dumps(metadata, indent=2) + "\n")
        assert metadata["source_image_id_after"] == source_before, "Gate image changed during benchmark"
        assert metadata["head_after"] == head and metadata["tracked_status_unchanged"], "Gate source changed during benchmark"


if __name__ == "__main__":
    main()
