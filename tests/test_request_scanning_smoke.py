from __future__ import annotations

import json
import runpy
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError

import pytest

HELPER = runpy.run_path("tests/integration/request-scanning.py")
TIMEOUT = {
    "error": "request_scan_unavailable",
    "message": "request safety scan timed out",
}


@pytest.fixture
def smoke_server():
    state = {
        "posts": [],
        "status": 503,
        "body": TIMEOUT,
        "retry_after": "1",
        "recover": True,
        "health_delay": 0,
        "heavy_delay": 0.2,
        "health_calls": 0,
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["health_calls"] += 1
            delay = state["health_delay"]
            state["health_delay"] = 0
            time.sleep(delay)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"alive"}')

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["posts"].append(body)
            heavy = (
                "metadata" in body.get("items", [{}])[0] or body.get("query") == "CI metadata scan"
            )
            if heavy:
                time.sleep(state["heavy_delay"])
            failed = heavy or not state["recover"]
            self.send_response(state["status"] if failed else 200)
            self.send_header("Retry-After", state["retry_after"])
            self.end_headers()
            result = (
                state["body"]
                if failed
                else {"success": True, "results": [{"id": "recovered", "text": "ordinary"}]}
            )
            self.wfile.write(json.dumps(result).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("operation", ["retain", "recall"])
def test_smoke_accepts_exact_timeout_only_after_clean_scan_recovers(
    smoke_server, monkeypatch, operation
):
    url, state = smoke_server
    if operation == "recall":
        state["body"] = {
            "error": "recall_scan_unavailable",
            "message": "recall safety scan timed out",
        }
    monkeypatch.setattr(sys, "argv", ["request-scanning.py", url, "test-token", operation])
    HELPER["main"]()
    assert len(state["posts"]) == 2
    recovered = state["posts"][1]
    assert (
        recovered.get("query") == "CI scanner recovery"
        if operation == "recall"
        else recovered == {"items": [{"content": "CI scanner recovery"}], "async": True}
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"status": 500},
        {"retry_after": "2"},
        {"body": {**TIMEOUT, "error": "hindsight_unavailable"}},
        {"body": {**TIMEOUT, "message": "request safety scanner worker failed"}},
        {"body": {**TIMEOUT, "results": [{"text": "partial leak"}]}},
    ],
)
def test_smoke_rejects_unexpected_error_or_partial_content(smoke_server, changes):
    url, state = smoke_server
    state.update(changes)
    with pytest.raises(AssertionError):
        HELPER["memory_request"](url, "test-token", "retain")


@pytest.mark.parametrize("operation", ["retain", "recall"])
def test_smoke_rejects_success_null_without_attempting_recovery(
    smoke_server, monkeypatch, operation
):
    url, state = smoke_server
    state.update(status=200, body=None)
    monkeypatch.setattr(sys, "argv", ["request-scanning.py", url, "test-token", operation])
    with pytest.raises(AssertionError):
        HELPER["main"]()
    assert len(state["posts"]) == 1


def test_smoke_rejects_timeout_when_clean_scan_cannot_recover(smoke_server, monkeypatch):
    url, state = smoke_server
    state["recover"] = False
    monkeypatch.setattr(sys, "argv", ["request-scanning.py", url, "test-token", "retain"])
    with pytest.raises(HTTPError):
        HELPER["main"]()


def test_smoke_rejects_timeout_when_liveness_was_blocked(smoke_server, monkeypatch):
    url, state = smoke_server
    state["health_delay"] = 1.05
    state["heavy_delay"] = 1.3
    monkeypatch.setattr(sys, "argv", ["request-scanning.py", url, "test-token", "retain"])
    with pytest.raises(AssertionError):
        HELPER["main"]()
    assert len(state["posts"]) == 1
    assert state["health_calls"] >= 3
