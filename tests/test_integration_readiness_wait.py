from __future__ import annotations

import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("delay", "status", "event", "budget", "succeeds"),
    [
        (5.2, 503, "hindsight_readiness_failed", 7, True),
        (5.2, 200, "hindsight_readiness_recovered", 7, True),
        (0, 200, "hindsight_readiness_failed", 2, False),
        (0, 503, "application_started", 2, False),
        (3, 503, "hindsight_readiness_failed", 2, False),
    ],
)
def test_readiness_wait_observes_slow_probe_without_weakening_gate(
    delay: float, status: int, event: str, budget: int, succeeds: bool
) -> None:
    expected_event = (
        "hindsight_readiness_recovered"
        if event == "hindsight_readiness_recovered"
        else "hindsight_readiness_failed"
    )
    expected_status = 200 if expected_event == "hindsight_readiness_recovered" else 503

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            time.sleep(delay)
            self.send_response(status)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    script = Path("tests/integration/smoke.sh").read_text()
    function = script.split("wait_for_readiness_event() {", 1)[1].split("\n}\n", 1)[0]
    # Exercise the checked-in shell function with a shorter overall test deadline.
    function = (
        "wait_for_readiness_event() {"
        + function.replace("SECONDS + 60", f"SECONDS + {budget}")
        + "\n}\n"
    )
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            harness = """set -euo pipefail
router_url="$1"
event_json="$2"
router_container=fixture
docker() { printf '%s\\n' "$event_json"; }
fail_check() { printf '%s\\n' "$1" >&2; exit 1; }
"""
            result = subprocess.run(  # noqa: S603 - checked-in function, loopback fixture
                [  # noqa: S607 - standard shell used by smoke.sh
                    "bash",
                    "-c",
                    harness
                    + function
                    + f"wait_for_readiness_event {expected_status} {expected_event} 0",
                    "readiness-test",
                    f"http://127.0.0.1:{server.server_port}",
                    json.dumps({"event": event}),
                ],
                capture_output=True,
                text=True,
                timeout=budget + 8,
            )
        finally:
            server.shutdown()
            thread.join(timeout=2)
    assert (result.returncode == 0) is succeeds, result.stderr
    if not succeeds:
        assert "readiness did not reach HTTP 503 with hindsight_readiness_failed" in result.stderr


@pytest.mark.parametrize("deadline_boundary", [True, False])
def test_readiness_wait_rejects_expired_deadline_and_stale_log(deadline_boundary: bool) -> None:
    script = Path("tests/integration/smoke.sh").read_text()
    function = script.split("wait_for_readiness_event() {", 1)[1].split("\n}\n", 1)[0]
    function = (
        "wait_for_readiness_event() {" + function.replace("SECONDS + 60", "SECONDS + 1") + "\n}\n"
    )
    harness = """set -euo pipefail
set -T
router_url=http://fixture
router_container=fixture
curl() { printf 'CURL_TIMEOUT=%s\\n' "$2" >&2; printf 503; }
docker() { printf '%s\\n' '{"event":"hindsight_readiness_failed"}' '{"event":"application_started"}'; }
fail_check() { printf '%s\\n' "$1" >&2; exit 1; }
"""
    if deadline_boundary:
        # Advance between the loop guard and remaining-time calculation.
        harness += "trap 'if [[ \"$BASH_COMMAND\" == request_timeout=* ]]; then SECONDS=$deadline; fi' DEBUG\n"
    result = subprocess.run(  # noqa: S603 - checked-in function, deterministic shell fixtures
        [  # noqa: S607 - standard shell used by smoke.sh
            "bash",
            "-c",
            harness
            + function
            + f"wait_for_readiness_event 503 hindsight_readiness_failed {0 if deadline_boundary else 1}",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1, result.stderr
    assert "readiness did not reach HTTP 503 with hindsight_readiness_failed" in result.stderr
    if deadline_boundary:
        assert "CURL_TIMEOUT=" not in result.stderr
