#!/usr/bin/env python3
"""Measure scan latency and peak scanner memory for one concurrency value.

Run it once for each candidate MEMORY_ROUTER_SCANNER_CONCURRENCY value on the
target host and compare the results. Linux only: it reads /proc.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import time
from pathlib import Path

from memory_router import scan_executor

_PAGE_KIB = os.sysconf("SC_PAGE_SIZE") // 1024
_BODY = {
    "items": [
        {
            "content": "The release test project uses Python and TypeScript. " * 150,
            "tags": ["bench"],
        }
    ]
}


def _scanner_rss_kib() -> int:
    """Return the resident memory of the direct child processes of this process."""
    total = 0
    for stat in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = stat.read_text().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if int(fields[1]) == os.getpid():
            total += int(fields[21]) * _PAGE_KIB
    return total


async def _measure(concurrency: int, scans: int) -> dict[str, float | int]:
    await asyncio.to_thread(scan_executor.start_scan_executor, concurrency)
    peak_kib = 0
    latencies: list[float] = []
    slots = asyncio.Semaphore(concurrency)

    async def scan() -> None:
        async with slots:
            started = time.perf_counter()
            await scan_executor.scan_request(_BODY, operation="retain")
            latencies.append((time.perf_counter() - started) * 1000)

    async def sample() -> None:
        nonlocal peak_kib
        while True:
            peak_kib = max(peak_kib, _scanner_rss_kib())
            await asyncio.sleep(0.05)

    sampler = asyncio.create_task(sample())
    started = time.perf_counter()
    try:
        await asyncio.gather(*(scan() for _ in range(scans)))
    finally:
        sampler.cancel()
        await scan_executor.shutdown_scan_executor_async()
    return {
        "concurrency": concurrency,
        "scans": scans,
        "scans_per_second": round(scans / (time.perf_counter() - started), 1),
        "latency_ms_p50": round(statistics.median(latencies), 1),
        "latency_ms_p95": round(statistics.quantiles(latencies, n=20)[18], 1),
        "peak_scanner_rss_mib": round(peak_kib / 1024, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--concurrency",
        type=int,
        choices=range(1, scan_executor.MAX_SCAN_CONCURRENCY + 1),
        default=scan_executor.DEFAULT_SCAN_CONCURRENCY,
        metavar=f"1-{scan_executor.MAX_SCAN_CONCURRENCY}",
    )
    parser.add_argument("--scans", type=int, default=200)
    arguments = parser.parse_args()
    print(json.dumps(asyncio.run(_measure(arguments.concurrency, arguments.scans))))


if __name__ == "__main__":
    main()
