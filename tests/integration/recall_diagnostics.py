from __future__ import annotations

import asyncio
import json
import os
from collections import Counter
from typing import Any, cast, get_args

from memory_router.db import PostgresDatabase, SqliteDatabase, is_postgres, sqlite_path
from memory_router.envelope import QuarantineReason
from memory_router.errors import HttpError
from memory_router.hindsight import HindsightGateway, recall_score_certification
from memory_router.scan_executor import (
    recall_response_scan_input,
    scan_recalled,
    shutdown_scan_executor_async,
    start_scan_executor,
)
from memory_router.security import scan_recall_response, scan_recall_result
from memory_router.security_models import SafetyFinding

_DETECTORS = frozenset(
    {
        "prompt_injection",
        "sensitive_data",
        "tool_abuse",
        "privilege_escalation",
        "excessive_autonomy",
    }
)

_SCORE_FIELDS = ("final", "reranker", "semantic", "keyword")
_MAX_SCORE_SCANS = 20
SCANNER_STARTUP_SECONDS = 60
_JSON_TYPES = {str: "string", int: "integer", float: "float", bool: "boolean", type(None): "null"}


def detector_counts(findings: list[SafetyFinding]) -> dict[str, int]:
    return dict(
        Counter(
            finding.detector if finding.detector in _DETECTORS else "other" for finding in findings
        )
    )


def score_diagnostics(response: dict[str, Any]) -> dict[str, Any]:
    observations = []
    omitted_results = []
    known_fields = 0
    for result in response["results"][:20]:
        copied = dict(result)
        fields = []
        if "weight" in copied:
            fields.append(("results[].weight", copied.pop("weight")))
        scores = copied.get("scores")
        if isinstance(scores, dict):
            copied["scores"] = dict(scores)
            for name in _SCORE_FIELDS:
                if name in scores:
                    fields.append((f"results[].scores.{name}", copied["scores"].pop(name)))
        omitted_results.append(copied)
        for path, value in fields:
            known_fields += 1
            if len(observations) >= _MAX_SCORE_SCANS:
                continue
            # Paths are fixed schema labels, never upstream key names or values.
            kind = _JSON_TYPES.get(type(value), "non_scalar")
            scan = (
                scan_recall_response({"results": [{"diagnostic_value": value}]})
                if kind != "non_scalar"
                else None
            )
            observations.append(
                {
                    "path": path,
                    "type": kind,
                    "safe": scan.safe if scan is not None else None,
                    "detectors": detector_counts(scan.findings) if scan is not None else {},
                }
            )
    # This copy is solely a diagnostic contrast; it is never released by the router.
    omitted_results.extend(response["results"][20:])
    omitted = scan_recall_response({**response, "results": omitted_results})
    return {
        "score_fields": observations,
        "score_fields_truncated": known_fields > len(observations) or len(response["results"]) > 20,
        "diagnostic_score_omission_result_count": min(20, len(response["results"])),
        "diagnostic_without_known_score_fields_safe": omitted.safe,
        "diagnostic_without_known_score_fields_detectors": detector_counts(omitted.findings),
    }


def upstream_summary(response: dict[str, Any], marker: str) -> dict[str, Any]:
    results = response["results"]
    findings = []
    unsafe_count = 0
    for result in results[:20]:
        scan = scan_recall_result(result)
        unsafe_count += not scan.safe
        findings.extend(scan.findings)
    aggregate = scan_recall_response(response)
    return {
        "result_count": len(results),
        "marker_result_count": sum(marker in result.get("text", "") for result in results),
        "entries_scanned": min(20, len(results)),
        "unsafe_entry_count": unsafe_count,
        "entry_detectors": detector_counts(findings),
        "raw_aggregate_safe": aggregate.safe,
        "raw_aggregate_detectors": detector_counts(aggregate.findings),
        **score_diagnostics(response),
    }


async def warm_scanner() -> None:
    # Standalone diagnostics have no application lifespan to warm spawned workers.
    async with asyncio.timeout(SCANNER_STARTUP_SECONDS):
        await asyncio.to_thread(start_scan_executor)
        while True:
            try:
                result = await scan_recalled({"id": "warmup", "text": "ordinary"})
            except HttpError as exc:
                if (
                    exc.status != 503
                    or exc.code != "recall_scan_unavailable"
                    or exc.message != "recall safety scan timed out"
                ):
                    raise
                await asyncio.sleep(1)
            else:
                assert result.safe
                return


async def production_summary(response: dict[str, object]) -> dict[str, object]:
    # This is a fresh upstream response, not the earlier blocked policy request.
    scan_input = recall_response_scan_input(response)
    results = cast(list[dict[str, object]], response["results"])
    statuses = Counter(recall_score_certification(result) for result in results)
    effective = scan_recall_response(scan_input)
    summary: dict[str, object] = {
        "capture": "fresh_upstream_response",
        "reviewed_result_count": 0,
        "score_certification": dict(statuses),
        "effective_aggregate_safe": effective.safe,
        "effective_aggregate_detectors": detector_counts(effective.findings),
    }
    try:
        await warm_scanner()
        worker = await scan_recalled(response, reviewed_result_positions=frozenset())
    except Exception:
        # Keep effective scanning and certification even if the worker is unavailable.
        # Exception messages can contain upstream data and must never be printed.
        summary["production_worker_available"] = False
    else:
        summary["production_worker_safe"] = worker.safe
        summary["production_worker_detectors"] = detector_counts(worker.findings)
    return summary


async def quarantine_reasons(url: str) -> dict[str, int]:
    database = PostgresDatabase(url) if is_postgres(url) else SqliteDatabase(sqlite_path(url))
    await database.initialize()
    try:
        async with database.transaction() as tx:
            rows = await tx.fetchall(
                "SELECT reason, COUNT(*) count FROM quarantine_items GROUP BY reason"
            )
        allowed = get_args(QuarantineReason)
        counts: Counter[str] = Counter()
        for row in rows:
            counts[row["reason"] if row["reason"] in allowed else "other"] += int(row["count"])
        return dict(counts)
    finally:
        await database.close()


async def main() -> None:
    summary: dict[str, Any] = {}
    try:
        summary["quarantine_reasons"] = await quarantine_reasons(
            os.environ["QUARANTINE_DATABASE_URL"]
        )
    except Exception:
        summary["quarantine_available"] = False
    print("HMR_RECALL_DIAGNOSTICS=" + json.dumps(summary, sort_keys=True), flush=True)
    summary = {}
    gateway = HindsightGateway(
        os.environ["HINDSIGHT_BASE_URL"], os.environ.get("HINDSIGHT_API_KEY"), timeout_ms=5_000
    )
    try:
        response = await gateway.recall("physical-main", {"query": os.environ["HMR_RECALL_MARKER"]})
    except Exception:
        summary["upstream_available"] = False
    else:
        summary["upstream_available"] = True
        try:
            summary["upstream"] = upstream_summary(response, os.environ["HMR_RECALL_MARKER"])
            summary["production"] = await production_summary(response)
        except Exception:
            summary["scanner_diagnostics_available"] = False
    finally:
        await gateway.close()
        await shutdown_scan_executor_async()
    print("HMR_RECALL_DIAGNOSTICS=" + json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
