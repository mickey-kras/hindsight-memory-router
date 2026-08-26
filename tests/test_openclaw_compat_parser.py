from __future__ import annotations

import pytest

from scripts.check_openclaw_compat import _supports_status, _upstream_operations


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


def test_upstream_openapi_parser_enforces_operation_floor() -> None:
    with pytest.raises(ValueError, match="expected at least 2"):
        _upstream_operations("openapi: 3.1.0\npaths: {}\n", minimum=2)


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

    with pytest.raises(Exception, match="duplicate key 'responses'"):
        _upstream_operations(source)
