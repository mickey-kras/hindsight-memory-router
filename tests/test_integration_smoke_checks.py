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

from tests.integration import recall_probe


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
        results = [{"text": "Retained CI_SMOKE_seed."}] if seed_appears and len(calls) > 1 else []
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
        with pytest.raises(TimeoutError, match="seeded marker"):
            recall_probe.wait_for_marker("http://127.0.0.1:8890", "test", "CI_SMOKE_seed", 5)
        assert clock[0] == 5
    assert all(0 < timeout <= 5 for _, timeout in calls)
    assert len(calls) <= 3


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
