from __future__ import annotations

import io
import json
import os
import subprocess
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO

import pytest

from memory_router.security_models import SafetyFinding
from tests.integration import recall_diagnostics, recall_probe


@pytest.mark.parametrize(
    "response",
    [
        {"results": [], "partial": True, "failed_banks": 1},
        {"results": [{"text": "CI_SMOKE_seed"}], "failed_banks": 1},
        {"results": None},
        {},
        [],
    ],
)
def test_recall_probe_rejects_degraded_or_malformed_results(response: object) -> None:
    with pytest.raises(ValueError):
        recall_probe.contains_marker(response, "CI_SMOKE_seed")


def test_recall_probe_requires_marker_in_memory_text() -> None:
    assert not recall_probe.contains_marker({"results": []}, "CI_SMOKE_seed")
    assert not recall_probe.contains_marker(
        {"results": [{"text": "unrelated", "metadata": {"marker": "CI_SMOKE_seed"}}]},
        "CI_SMOKE_seed",
    )
    assert recall_probe.contains_marker(
        {"results": [{"text": "Retained CI_SMOKE_seed."}]}, "CI_SMOKE_seed"
    )


@pytest.mark.parametrize("seed_appears", [True, False])
def test_recall_probe_waits_for_async_retain_only_until_its_deadline(
    monkeypatch: pytest.MonkeyPatch, seed_appears: bool
) -> None:
    clock = [0.0]
    calls = []

    def advance(seconds: float) -> None:
        clock[0] += seconds

    def open_response(request: urllib.request.Request, timeout: float) -> io.BytesIO:
        calls.append((request, timeout))
        results = (
            [{"text": "Retained CI_SMOKE_seed."}]
            if seed_appears and len(calls) > 1
            else [{"id": "PRIVATE-ID", "text": "PRIVATE-CONTENT"}]
        )
        return io.BytesIO(json.dumps({"results": results}).encode())

    monkeypatch.setattr(recall_probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(recall_probe.time, "sleep", advance)
    monkeypatch.setattr(
        recall_probe.urllib.request, "build_opener", lambda *_: SimpleNamespace(open=open_response)
    )
    if seed_appears:
        result = recall_probe.wait_for_marker("http://127.0.0.1:8890", "test", "CI_SMOKE_seed", 5)
        assert result["results"][0]["text"] == "Retained CI_SMOKE_seed."
    else:
        with pytest.raises(TimeoutError, match="seeded marker") as error:
            recall_probe.wait_for_marker("http://127.0.0.1:8890", "test", "CI_SMOKE_seed", 5)
        assert clock[0] == 5
        assert '"result_count": 1' in str(error.value)
        assert '"partial": false' in str(error.value)
        assert '"failed_bank_count": 0' in str(error.value)
        assert "PRIVATE" not in str(error.value)
    assert all(0 < timeout <= 5 for _, timeout in calls)
    assert len(calls) <= 3


def test_recall_diagnostics_report_counts_without_private_values() -> None:
    summary = recall_diagnostics.upstream_summary(
        {"results": [{"id": "PRIVATE-ID", "text": "PRIVATE-MARKER", "score": 0.4111111111111111}]},
        "PRIVATE-MARKER",
    )
    assert summary["result_count"] == summary["marker_result_count"] == 1
    assert summary["unsafe_entry_count"] == 0
    assert summary["raw_aggregate_safe"] is False
    assert summary["raw_aggregate_detectors"] == {"sensitive_data": 1}
    assert "PRIVATE" not in json.dumps(summary)
    assert "HIDDEN" not in json.dumps(summary)
    assert "4111111111111111" not in json.dumps(summary)
    assert recall_diagnostics.detector_counts(
        [
            SafetyFinding(
                "PRIVATE-MATCH", "PRIVATE-REASON", "PRIVATE-DETECTOR", hits=("PRIVATE-HIT",)
            )
        ]
    ) == {"other": 1}


def test_score_diagnostics_identify_structural_field_without_mutating_response() -> None:
    response = {
        "results": [
            {
                "id": "PRIVATE-ID",
                "text": "ordinary",
                "weight": 0.5,
                "scores": {
                    "final": 0.5,
                    "reranker": 0.4111111111111111,
                    "HIDDEN-FIELD": "ordinary",
                },
            }
        ]
    }
    original = json.dumps(response)
    summary = recall_diagnostics.score_diagnostics(response)
    assert summary["score_fields"] == [
        {"path": "results[].weight", "type": "float", "safe": True, "detectors": {}},
        {"path": "results[].scores.final", "type": "float", "safe": True, "detectors": {}},
        {
            "path": "results[].scores.reranker",
            "type": "float",
            "safe": False,
            "detectors": {"sensitive_data": 1},
        },
    ]
    assert summary["diagnostic_without_known_score_fields_safe"] is True
    assert not summary["score_fields_truncated"]
    assert json.dumps(response) == original
    assert "PRIVATE" not in json.dumps(summary)
    assert "HIDDEN" not in json.dumps(summary)
    assert "4111111111111111" not in json.dumps(summary)


def test_score_diagnostics_remain_bounded_and_keep_unknown_fields() -> None:
    response = {"results": [{"scores": {"final": 0.5}} for _ in range(25)]}
    summary = recall_diagnostics.score_diagnostics(response)
    assert len(summary["score_fields"]) == 20
    assert summary["score_fields_truncated"]
    summary = recall_diagnostics.score_diagnostics(
        {"results": [{"scores": {"final": 0.5, "HIDDEN-FIELD": 0.4111111111111111}}]}
    )
    assert summary["diagnostic_without_known_score_fields_safe"] is False
    assert summary["diagnostic_without_known_score_fields_detectors"] == {"sensitive_data": 1}
    assert "PRIVATE" not in json.dumps(summary)
    assert "HIDDEN" not in json.dumps(summary)


@pytest.fixture
def fake_llm_url(tmp_path: Path) -> Iterator[str]:
    ready_path = tmp_path / "fake-llm-ready.json"
    with (tmp_path / "fake-llm.log").open("w+b") as log:
        process = subprocess.Popen(  # noqa: S603 - checked-in integration fixture
            ["node", str(Path("tests/integration/fake-llm.js").resolve())],  # noqa: S607
            env={**os.environ, "PORT": "0", "READY_FILE": str(ready_path)},
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            deadline = time.monotonic() + 15
            while True:
                exit_code = process.poll()
                remaining = deadline - time.monotonic()
                if exit_code is not None or remaining <= 0:
                    reason = (
                        f"exited with code {exit_code}"
                        if exit_code is not None
                        else "timed out after 15 seconds"
                    )
                    log.seek(max(0, log.seek(0, os.SEEK_END) - 4096))
                    diagnostics = log.read(4096).decode("utf-8", errors="replace")
                    raise RuntimeError(f"fake LLM {reason}\n{diagnostics}")
                try:
                    port = json.loads(ready_path.read_text())["port"]
                    base_url = f"http://127.0.0.1:{port}"
                    with opener.open(  # noqa: S310 - loopback fixture
                        f"{base_url}/health", timeout=min(0.2, remaining)
                    ):
                        break
                except (OSError, ValueError):
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            yield base_url
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.mark.parametrize("exit_code", [42, None])
def test_fake_llm_startup_reports_bounded_logs_and_reaps_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exit_code: int | None
) -> None:
    actions: list[str] = []
    clock = iter((0.0, 16.0))

    def wait(timeout: float) -> int:
        actions.append("wait")
        if exit_code is None and "kill" not in actions:
            raise subprocess.TimeoutExpired("node", timeout)
        return exit_code or -9

    def start(
        command: list[str], *, env: dict[str, str], stdout: BinaryIO, stderr: int
    ) -> SimpleNamespace:
        stdout.write(b"discarded-prefix" + b"x" * 5000 + b"startup diagnostic")
        stdout.flush()
        assert env["PORT"] == "0"
        return SimpleNamespace(
            poll=lambda: exit_code,
            terminate=lambda: actions.append("terminate"),
            kill=lambda: actions.append("kill"),
            wait=wait,
        )

    monkeypatch.setattr(subprocess, "Popen", start)
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))
    reason = "exited with code 42" if exit_code is not None else "timed out after 15 seconds"
    fixture = fake_llm_url.__wrapped__(tmp_path)
    with pytest.raises(RuntimeError, match=reason) as error:
        next(fixture)
    assert "startup diagnostic" in str(error.value)
    assert "discarded-prefix" not in str(error.value)
    assert len(str(error.value)) < 4200
    assert actions == (
        ["wait"] if exit_code is not None else ["terminate", "wait", "kill", "wait"]
    )


def test_fake_embeddings_keep_query_and_passage_vectors_identical(fake_llm_url: str) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    vectors = []
    for inputs in ("a recall query", ["a retained passage", "a different passage"]):
        request = urllib.request.Request(  # noqa: S310 - loopback fixture
            fake_llm_url + "/v1/embeddings",
            data=json.dumps({"model": "ci-fake", "input": inputs, "dimensions": 384}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with opener.open(request, timeout=2) as response:  # noqa: S310 - loopback fixture
            items = json.load(response)["data"]
        assert [item["index"] for item in items] == list(
            range(len(inputs) if isinstance(inputs, list) else 1)
        )
        vectors.extend(item["embedding"] for item in items)
    assert len(vectors) == 3
    assert all(len(vector) == 384 for vector in vectors)
    assert vectors[0] == vectors[1] == vectors[2]
    assert sum(value * value for value in vectors[0]) == 1


@pytest.mark.parametrize("endpoint", ["/api/chat", "/v1/chat/completions"])
def test_fake_llm_extracts_only_a_marker_actually_supplied_for_retain(
    fake_llm_url: str, endpoint: str
) -> None:
    fields = ("what", "when", "where", "who", "why", "fact_type")
    schema = {
        "type": "object",
        "required": ["facts"],
        "properties": {"facts": {"type": "array", "items": {"$ref": "#/$defs/Fact"}}},
        "$defs": {
            "Fact": {
                "type": "object",
                "properties": {field: {"type": "string"} for field in fields},
                "required": list(fields),
            }
        },
    }
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for content in ("Retain CI_SMOKE_unique_123", "Retain an unrelated fact"):
        body = {"messages": [{"role": "user", "content": content}]}
        if endpoint == "/api/chat":
            body["format"] = schema
        else:
            body["response_format"] = {"type": "json_schema", "json_schema": {"schema": schema}}
        request = urllib.request.Request(  # noqa: S310 - loopback fixture
            fake_llm_url + endpoint,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with opener.open(request, timeout=2) as response:  # noqa: S310 - loopback fixture
            result = json.load(response)
        message = result["message"] if endpoint == "/api/chat" else result["choices"][0]["message"]
        facts = json.loads(message["content"])["facts"]
        if "CI_SMOKE_unique_123" in content:
            assert len(facts) == 1 and "CI_SMOKE_unique_123" in facts[0]["what"]
            assert set(fields) <= facts[0].keys()
        else:
            assert facts == []
