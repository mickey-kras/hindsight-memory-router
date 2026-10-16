from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

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
def fake_llm_url() -> Iterator[str]:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen(  # noqa: S603 - checked-in integration fixture
        ["node", str(Path("tests/integration/fake-llm.js").resolve())],  # noqa: S607
        env={**os.environ, "PORT": str(port)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base_url = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                with opener.open(f"{base_url}/health", timeout=0.2):  # noqa: S310 - loopback fixture
                    break
            except OSError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("fake LLM failed to start") from None
                time.sleep(0.05)
        yield base_url
    finally:
        process.terminate()
        process.wait(timeout=5)


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
