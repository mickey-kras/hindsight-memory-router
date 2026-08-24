from __future__ import annotations

import pytest

from scripts.check_openclaw_compat import _supports_status, _upstream_operations


def test_upstream_openapi_parser_handles_yaml_renderings_without_status_leak() -> None:
    source = """
openapi: 3.1.0
paths:
  /first:
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
        "query": {"q": True},
        "statuses": {"200"},
    }
    second = operations[("POST", "/second")]
    assert second["statuses"] == {"2XX"}
    assert second["deprecated"] is True
    assert _supports_status(first["statuses"], 200)
    assert not _supports_status(first["statuses"], 201)
    assert _supports_status(second["statuses"], 201)


def test_upstream_openapi_parser_enforces_operation_floor() -> None:
    with pytest.raises(ValueError, match="expected at least 2"):
        _upstream_operations("openapi: 3.1.0\npaths: {}\n", minimum=2)
