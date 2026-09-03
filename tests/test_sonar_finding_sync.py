from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import urllib.error
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture(scope="module")
def sync_module() -> ModuleType:
    path = Path(".github/scripts/sync-sonar-findings.py")
    spec = importlib.util.spec_from_file_location("sync_sonar_findings", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def github_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("SONAR_HOST_URL", "https://sonar.example")


def test_two_hotspots_create_two_stable_findings(sync_module: ModuleType) -> None:
    gate = {
        "projectStatus": {
            "conditions": [
                {
                    "status": "ERROR",
                    "metricKey": "new_security_hotspots_reviewed",
                    "actualValue": "0.0",
                    "comparator": "LT",
                    "errorThreshold": "100",
                }
            ]
        }
    }
    hotspots = [
        {
            "key": "hotspot-1",
            "component": "router:memory_router/app.py",
            "line": 10,
            "message": "Review this use of subprocess",
        },
        {
            "key": "hotspot-2",
            "component": "router:memory_router/security.py",
            "line": 20,
            "message": "Review this regular expression",
        },
    ]

    findings = sync_module.tracked_findings(gate, [], hotspots, "router")

    assert [finding.key for finding in findings] == ["hotspot-hotspot-1", "hotspot-hotspot-2"]
    assert all("Detected at commit: `abc123`" in finding.body for finding in findings)


def test_individual_issue_and_aggregate_metric_are_both_tracked(sync_module: ModuleType) -> None:
    gate = {
        "projectStatus": {
            "conditions": [
                {
                    "status": "ERROR",
                    "metricKey": "new_coverage",
                    "actualValue": "79.0",
                    "comparator": "LT",
                    "errorThreshold": "80",
                }
            ]
        }
    }
    issues = [
        {
            "key": "issue-1",
            "component": "router:memory_router/app.py",
            "line": 30,
            "message": "Refactor this function",
            "type": "CODE_SMELL",
            "severity": "MAJOR",
            "rule": "python:S3776",
        }
    ]

    findings = sync_module.tracked_findings(gate, issues, [], "router")

    assert [finding.key for finding in findings] == ["issue-issue-1", "condition-new_coverage"]
    assert "Rule: `python:S3776`" in findings[0].body
    assert "Actual: `79.0`" in findings[1].body


def test_failed_condition_is_fallback_when_no_findings_are_returned(
    sync_module: ModuleType,
) -> None:
    gate = {
        "projectStatus": {
            "conditions": [
                {
                    "status": "ERROR",
                    "metricKey": "new_reliability_rating",
                    "actualValue": "3",
                    "comparator": "GT",
                    "errorThreshold": "1",
                }
            ]
        }
    }

    findings = sync_module.tracked_findings(gate, [], [], "router")

    assert len(findings) == 1
    assert findings[0].key == "condition-new_reliability_rating"


def test_optional_paged_falls_back_only_for_forbidden(sync_module: ModuleType) -> None:
    class Client:
        @staticmethod
        def paged(*_: object, **__: object) -> list[dict[str, object]]:
            raise urllib.error.HTTPError("https://sonar.example", 403, "", {}, None)

    assert sync_module.optional_paged(Client(), "/api/issues/search", "issues") == []


def test_optional_paged_preserves_other_http_errors(sync_module: ModuleType) -> None:
    class Client:
        @staticmethod
        def paged(*_: object, **__: object) -> list[dict[str, object]]:
            raise urllib.error.HTTPError("https://sonar.example", 500, "", {}, None)

    with pytest.raises(urllib.error.HTTPError):
        sync_module.optional_paged(Client(), "/api/issues/search", "issues")


def test_existing_closed_finding_is_reopened_not_duplicated(sync_module: ModuleType) -> None:
    calls: list[tuple[str, ...]] = []

    def run(args: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:3] == ("gh", "issue", "list"):
            stdout = json.dumps(
                [
                    {
                        "number": 180,
                        "state": "CLOSED",
                        "body": "<!-- sonar-finding:hotspot-stable-key -->",
                    }
                ]
            )
        else:
            stdout = ""
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    tracker = sync_module.GitHubTracker("owner", run=run)
    reference = tracker.upsert(
        sync_module.TrackedFinding("hotspot-stable-key", "title", "updated body")
    )

    assert reference == "#180"
    assert any(call[:4] == ("gh", "issue", "reopen", "180") for call in calls)
    assert any(call[:4] == ("gh", "issue", "edit", "180") for call in calls)
    assert not any(call[:3] == ("gh", "issue", "create") for call in calls)
