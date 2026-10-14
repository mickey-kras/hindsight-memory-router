"""Test synchronization and clocks scoped to scanner deadline arithmetic."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Literal
from unittest.mock import patch

from memory_router import scan_executor, security, security_base64, security_rules, unicode_security
from memory_router.security import SafetyResult


@contextmanager
def scanner_clock(*, step: float = 0.0) -> Iterator[None]:
    # Replace the scanner modules' clock references, never the shared time module:
    # event-loop scheduling, process timeouts and cancellation keep their real clocks.
    elapsed = 0.0

    def monotonic() -> float:
        nonlocal elapsed
        now = elapsed
        elapsed += step
        return now

    clock = SimpleNamespace(monotonic=monotonic)
    with ExitStack() as stack:
        for module in (security, security_base64, security_rules):
            stack.enter_context(patch.object(module, "time", clock))
        stack.enter_context(patch.object(unicode_security, "monotonic", clock.monotonic))
        yield


def synchronized_scan(
    payload: bytes, *, kind: Literal["request", "recall", "block"], entered: Path, release: Path
) -> SafetyResult:
    entering = entered.with_suffix(".tmp")
    entering.write_text(str(os.getpid()))
    entering.replace(entered)
    deadline = time.monotonic() + 15
    while not release.exists():
        if time.monotonic() > deadline:
            raise TimeoutError("test did not release the scanner")
        time.sleep(0.01)
    if kind == "block":
        return SafetyResult()
    # Responsiveness depends on process isolation, not how many seconds the
    # workload takes. Advance only scanner deadline arithmetic deterministically.
    with scanner_clock(step=0.01):
        scanner = (
            scan_executor._scan_request_payload
            if kind == "request"
            else scan_executor._scan_recalled_payload
        )
        return scanner(payload)


def blocked_scan(payload: bytes, *, entered_dir: Path, release: Path) -> SafetyResult:
    return synchronized_scan(
        payload, kind="block", entered=entered_dir / str(os.getpid()), release=release
    )
