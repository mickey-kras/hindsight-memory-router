from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from unittest.mock import AsyncMock

import pytest

from memory_router.errors import HttpError
from memory_router.security import SafetyResult
from tests.integration import recall_diagnostics as diagnostic


@pytest.mark.parametrize("delay_seconds", [8, 14])
def test_diagnostic_file_invocation_waits_for_delayed_spawn(
    tmp_path: Path, delay_seconds: int
) -> None:
    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"results":[{"id":"fixture","text":"ordinary"}]}')

        def log_message(self, *_args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # A real main file is required for multiprocessing spawn to import its entry point.
    entry = tmp_path / "diagnostic_entry.py"
    entry.write_text(
        "import asyncio, multiprocessing, runpy, time\n"
        "from functools import partial\n"
        "from pebble import ProcessPool\n"
        "from memory_router import scan_executor\n"
        "if __name__ == '__main__':\n"
        "    scan_executor._new_scan_executor = lambda: ProcessPool(\n"
        "        max_workers=1, context=multiprocessing.get_context('spawn'),\n"
        f"        initializer=partial(time.sleep, {delay_seconds}))\n"
        f"    probe = runpy.run_path({str(Path(diagnostic.__file__).resolve())!r})\n"
        "    asyncio.run(probe['main']())\n"
    )
    try:
        process = subprocess.run(  # noqa: S603 - fixed local regression entry point
            [sys.executable, str(entry)],
            env={
                **os.environ,
                "HINDSIGHT_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                "HMR_RECALL_MARKER": "ordinary",
                "QUARANTINE_DATABASE_URL": f"sqlite:{tmp_path / 'quarantine.db'}",
            },
            capture_output=True,
            text=True,
            timeout=85,
            check=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    records = [json.loads(line.split("=", 1)[1]) for line in process.stdout.splitlines()]
    assert len(records) == 2
    assert records[1]["upstream_available"] is True
    assert records[1]["production"]["production_worker_safe"] is True
    assert "ordinary" not in process.stdout
    assert set(process.stderr.splitlines()) == {"recall_scan_failed"}
    smoke = Path("tests/integration/smoke.sh").read_text()
    copy = "cp tests/integration/recall_diagnostics.py memory-router:/tmp/recall_diagnostics.py"
    assert copy in smoke
    assert smoke.count("timeout 90 python /tmp/recall_diagnostics.py") == 2
    assert "python < tests/integration/recall_diagnostics.py" not in smoke


@pytest.mark.parametrize(
    "error",
    [
        HttpError(503, "recall_scan_unavailable", "recall safety scanner is busy"),
        HttpError(503, "recall_scan_unavailable", "recall safety scanner worker failed"),
        HttpError(500, "recall_scan_unavailable", "recall safety scan timed out"),
    ],
)
async def test_worker_failure_preserves_effective_diagnostics(
    monkeypatch: pytest.MonkeyPatch, error: HttpError
) -> None:
    scan = AsyncMock(side_effect=error)
    monkeypatch.setattr(diagnostic, "start_scan_executor", lambda: None)
    monkeypatch.setattr(diagnostic, "scan_recalled", scan)
    summary = await diagnostic.production_summary({"results": [{"text": "ordinary"}]})
    assert summary == {
        "capture": "fresh_upstream_response",
        "reviewed_result_count": 0,
        "score_certification": {"ineligible": 1},
        "effective_aggregate_safe": True,
        "effective_aggregate_detectors": {},
        "production_worker_available": False,
    }
    scan.assert_awaited_once()


async def test_diagnostic_startup_has_overall_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    async def stalled_scan(*_args: Any, **_kwargs: Any) -> SafetyResult:
        await asyncio.Event().wait()
        return SafetyResult()

    monkeypatch.setattr(diagnostic, "SCANNER_STARTUP_SECONDS", 0.01)
    monkeypatch.setattr(diagnostic, "start_scan_executor", lambda: None)
    monkeypatch.setattr(diagnostic, "scan_recalled", stalled_scan)
    summary = await diagnostic.production_summary({"results": []})
    assert summary["production_worker_available"] is False
    assert summary["effective_aggregate_safe"] is True


@pytest.mark.parametrize("failure", ["upstream", "scanner"])
async def test_diagnostic_distinguishes_upstream_and_scanner_failures(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], failure: str
) -> None:
    gateway = AsyncMock()
    gateway.recall.return_value = {"results": []}
    if failure == "upstream":
        gateway.recall.side_effect = RuntimeError("PRIVATE-UPSTREAM")
    monkeypatch.setattr(diagnostic, "HindsightGateway", lambda *_args, **_kwargs: gateway)
    monkeypatch.setattr(diagnostic, "quarantine_reasons", AsyncMock(return_value={}))
    monkeypatch.setattr(diagnostic, "shutdown_scan_executor_async", AsyncMock())
    if failure == "scanner":
        monkeypatch.setattr(
            diagnostic,
            "upstream_summary",
            lambda *_args: (_ for _ in ()).throw(RuntimeError("PRIVATE-SCANNER")),
        )
    monkeypatch.setenv("QUARANTINE_DATABASE_URL", "unused")
    monkeypatch.setenv("HINDSIGHT_BASE_URL", "unused")
    monkeypatch.setenv("HMR_RECALL_MARKER", "PRIVATE-MARKER")
    await diagnostic.main()
    output = capsys.readouterr().out
    records = [json.loads(line.split("=", 1)[1]) for line in output.splitlines()]
    expected = {"upstream_available": failure != "upstream"}
    if failure == "scanner":
        expected["scanner_diagnostics_available"] = False
    assert records == [{"quarantine_reasons": {}}, expected]
    assert "PRIVATE" not in output
    gateway.close.assert_awaited_once()
