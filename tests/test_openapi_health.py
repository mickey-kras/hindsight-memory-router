from __future__ import annotations

import json
from pathlib import Path


def _document() -> dict[str, object]:
    return json.loads(Path("openapi/openapi.json").read_text())


def test_health_openapi_contract() -> None:
    document = _document()
    paths = document["paths"]
    assert isinstance(paths, dict)

    for path in ("/health", "/health/ready", "/health/live", "/ready"):
        operation = paths[path]["get"]
        assert operation["security"] == []

    health = paths["/health"]["get"]
    ready = paths["/health/ready"]["get"]
    for status in ("200", "503"):
        assert health["responses"][status] == ready["responses"][status]
    assert health["responses"]["200"]["content"]["application/json"]["schema"] == {}
    assert health["responses"]["503"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/HealthUnavailableResponse"
    }

    live = paths["/health/live"]["get"]
    assert "503" not in live["responses"]
    assert live["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/LivenessResponse"
    }

    legacy = paths["/ready"]["get"]
    assert legacy["deprecated"] is True
    assert legacy["responses"] == ready["responses"]

    schemas = document["components"]["schemas"]
    assert schemas["LivenessResponse"] == {
        "type": "object",
        "additionalProperties": False,
        "required": ["status"],
        "properties": {"status": {"type": "string", "const": "healthy"}},
    }
    assert schemas["HealthUnavailableResponse"] == {
        "type": "object",
        "additionalProperties": False,
        "required": ["status"],
        "properties": {"status": {"type": "string", "const": "unhealthy"}},
    }
    assert "router_health" not in json.dumps(document)
