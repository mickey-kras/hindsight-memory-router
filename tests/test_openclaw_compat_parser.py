from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from yaml.constructor import ConstructorError

from scripts import check_openclaw_compat as compat
from scripts.check_openclaw_compat import (
    REQUIRED_COVERAGE_MARKERS,
    _missing_coverage_markers,
    _supports_status,
    _upstream_operations,
)


def test_inventory_reports_removed_upstream_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "compat").mkdir()
    (tmp_path / "compat/openclaw.json").write_text(
        json.dumps(
            {
                "sources": {"memory_provider": "missing.ts"},
                "source_blob_shas": {},
            }
        )
    )
    monkeypatch.setattr(compat, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["check_openclaw_compat.py", str(tmp_path)])

    with pytest.raises(SystemExit, match="upstream compatibility source missing: memory_provider"):
        compat.main()


def test_inventory_rejects_unreviewed_upstream_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "compat").mkdir()
    (tmp_path / "plugin.ts").write_text("changed upstream behavior")
    (tmp_path / "compat/openclaw.json").write_text(
        json.dumps(
            {
                "sources": {"plugin": "plugin.ts"},
                "source_blob_shas": {"plugin": "0" * 40},
            }
        )
    )
    monkeypatch.setattr(compat, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["check_openclaw_compat.py", str(tmp_path)])

    with pytest.raises(SystemExit, match="refresh inventory: \\['plugin'\\]"):
        compat.main()


def test_upstream_canary_runs_independently_with_read_only_resolved_sources() -> None:
    root = Path(__file__).parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/upstream-compatibility.yml").read_text())
    triggers = workflow[True]
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert triggers["schedule"]
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["compatibility"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert "permissions" not in job
    upstream = next(step for step in job["steps"] if step.get("with", {}).get("repository"))
    assert upstream["with"] == {
        "repository": "vectorize-io/hindsight",
        "ref": "${{ steps.upstream.outputs.sha }}",
        "path": ".upstream/hindsight",
        "persist-credentials": False,
    }
    assert job["steps"][-1]["run"] == "python scripts/check_openclaw_compat.py .upstream/hindsight"


def test_compat_script_invokes_main_when_executed() -> None:
    script = Path(__file__).parents[1] / "scripts" / "check_openclaw_compat.py"

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [sys.executable, str(script)], capture_output=True, check=False, text=True
    )

    assert completed.returncode != 0
    assert "usage: check_openclaw_compat.py <hindsight-checkout>" in completed.stderr


def test_upstream_openapi_parser_handles_yaml_renderings_without_status_leak() -> None:
    source = """
openapi: 3.1.0
paths:
  /first:
    parameters:
      - {name: shared, in: query, required: false, schema: {type: string}}
    get:
      requestBody:
        required: true
      parameters:
        - {name: q, in: query, required: true, schema: {type: string}}
      responses: {200: {description: ok}} # unquoted flow-style status
  /second:
    post:
      deprecated: true
      responses:
        "2XX":
          description: any success
"""

    operations = _upstream_operations(source, minimum=2)

    first = operations[("GET", "/first")]
    assert first == {
        "body": "required",
        "deprecated": False,
        "query": {"shared": False, "q": True},
        "statuses": {"200"},
    }
    second = operations[("POST", "/second")]
    assert second["statuses"] == {"2XX"}
    assert second["deprecated"] is True
    assert _supports_status(first["statuses"], 200)
    assert not _supports_status(first["statuses"], 201)
    assert _supports_status(second["statuses"], 201)
    assert _supports_status({"DEFAULT"}, 204)


def test_upstream_openapi_parser_enforces_operation_floor() -> None:
    with pytest.raises(ValueError, match="expected at least 2"):
        _upstream_operations("openapi: 3.1.0\npaths: {}\n", minimum=2)


def test_operation_parameter_overrides_shared_parameter() -> None:
    source = """
openapi: 3.1.0
paths:
  /first:
    parameters:
      - {name: q, in: query, required: false}
    get:
      parameters:
        - {name: q, in: query, required: true}
      responses: {200: {description: ok}}
"""

    operation = _upstream_operations(source)[("GET", "/first")]

    assert operation["query"] == {"q": True}


def test_yaml_merge_keys_fail_loud() -> None:
    source = """
openapi: 3.1.0
defaults: &defaults
  deprecated: false
  responses: {200: {description: default}}
paths:
  /first:
    get:
      <<: *defaults
      responses: {201: {description: overridden}}
"""

    with pytest.raises(ConstructorError, match="YAML merge keys are not supported"):
        _upstream_operations(source)


def test_yaml_merge_sequence_cannot_mask_source_key_collisions() -> None:
    source = """
openapi: 3.1.0
first: &first {deprecated: false, responses: {200: {description: first}}}
second: &second {deprecated: true, responses: {201: {description: second}}}
paths:
  /first:
    get:
      <<: [*first, *second]
"""

    with pytest.raises(ConstructorError, match="YAML merge keys are not supported"):
        _upstream_operations(source)


def test_coverage_marker_check_fails_when_any_marker_is_removed() -> None:
    source = "\n".join(REQUIRED_COVERAGE_MARKERS - {"auto-recall"})

    assert _missing_coverage_markers(source) == ["auto-recall"]


def test_yaml_unhashable_mapping_key_has_hygienic_error() -> None:
    source = """
openapi: 3.1.0
paths:
  ? [unhashable]
  : {get: {responses: {200: {description: ok}}}}
"""

    with pytest.raises(ConstructorError, match="unhashable mapping key"):
        _upstream_operations(source)


@pytest.mark.parametrize(
    "operation",
    [
        "requestBody: {$ref: '#/components/requestBodies/Body'}",
        "parameters: [{$ref: '#/components/parameters/Query'}]",
    ],
)
def test_upstream_openapi_parser_rejects_unresolved_refs(operation: str) -> None:
    source = f"""
openapi: 3.1.0
paths:
  /first:
    get:
      {operation}
      responses: {{200: {{description: ok}}}}
"""

    with pytest.raises(ValueError, match=r"unsupported .+ \$ref"):
        _upstream_operations(source)


def test_upstream_openapi_parser_rejects_path_item_ref() -> None:
    source = """
openapi: 3.1.0
paths:
  /first:
    $ref: '#/components/pathItems/First'
"""

    with pytest.raises(ValueError, match=r"unsupported path-item \$ref"):
        _upstream_operations(source)


def test_upstream_openapi_parser_rejects_shared_parameter_ref() -> None:
    source = """
openapi: 3.1.0
paths:
  /first:
    parameters:
      - {$ref: '#/components/parameters/Query'}
    get:
      responses: {200: {description: ok}}
"""

    with pytest.raises(ValueError, match=r"unsupported parameter \$ref"):
        _upstream_operations(source)


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        (
            "parameters: [{name: on, in: query}]\n      responses: {200: {}}",
            "parameter name/in must be strings",
        ),
        (
            "parameters: [{name: q, in: query}, {name: q, in: query}]\n      responses: {200: {}}",
            "duplicate parameter query:q",
        ),
        ("deprecated: 'true'\n      responses: {200: {}}", "deprecated must be boolean"),
    ],
)
def test_upstream_openapi_parser_rejects_silent_coercions(operation: str, message: str) -> None:
    source = f"""
openapi: 3.1.0
paths:
  /first:
    get:
      {operation}
"""

    with pytest.raises(ValueError, match=message):
        _upstream_operations(source)


def test_upstream_openapi_parser_rejects_duplicate_mapping_keys() -> None:
    source = """
openapi: 3.1.0
paths:
  /first:
    get:
      responses: {200: {description: first}}
      responses: {201: {description: second}}
"""

    with pytest.raises(ConstructorError, match="duplicate key 'responses'"):
        _upstream_operations(source)


def test_upstream_openapi_parser_reports_excessive_nesting() -> None:
    nested = "[" * 2_000 + "null" + "]" * 2_000
    source = (
        f"paths:\n  /v1/test:\n    get:\n      responses:\n        '200':\n          x: {nested}\n"
    )

    with pytest.raises(ValueError, match="nesting is too deep"):
        _upstream_operations(source)
