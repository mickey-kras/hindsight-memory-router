from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def _methods(source: str, receivers: tuple[str, ...]) -> set[str]:
    joined = "|".join(re.escape(receiver) for receiver in receivers)
    return set(re.findall(rf"(?:{joined})\.([A-Za-z][A-Za-z0-9_]*)\s*\(", source))


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_openclaw_compat.py <hindsight-checkout>")

    root = Path(sys.argv[1])
    inventory = json.loads(Path("compat/openclaw.json").read_text(encoding="utf-8"))
    plugin = (root / inventory["sources"]["plugin"]).read_text(encoding="utf-8")
    defaults = (root / inventory["sources"]["bank_defaults"]).read_text(encoding="utf-8")
    sdk = (root / inventory["sources"]["agent_sdk"]).read_text(encoding="utf-8")

    expected_plugin = set(inventory["plugin_client_methods"])
    actual_plugin = _methods(plugin, ("client", "c")) & {
        "createBank",
        "recall",
        "retain",
        "retainBatch",
        "reflect",
        "listMentalModels",
        "getMentalModel",
        "createMentalModel",
        "updateMentalModel",
        "deleteMentalModel",
    }
    if actual_plugin != expected_plugin:
        raise SystemExit(
            f"OpenClaw Hindsight client surface changed: expected {sorted(expected_plugin)}, "
            f"found {sorted(actual_plugin)}"
        )

    expected_sdk = set(inventory["agent_sdk_methods"])
    actual_sdk = _methods(sdk, ("client", "sdk")) & {
        "createBank",
        "recall",
        "retain",
        "retainBatch",
        "reflect",
        "listMentalModels",
        "getMentalModel",
        "createMentalModel",
        "updateMentalModel",
        "deleteMentalModel",
    }
    if actual_sdk != expected_sdk:
        raise SystemExit(
            f"OpenClaw agent SDK surface changed: expected {sorted(expected_sdk)}, "
            f"found {sorted(actual_sdk)}"
        )

    required_plugin_markers = ("/health", "/version")
    for marker in required_plugin_markers:
        if marker not in plugin:
            raise SystemExit(f"OpenClaw plugin no longer contains required probe {marker}")
    if "/config" not in defaults or "method: \"PATCH\"" not in defaults:
        raise SystemExit("OpenClaw bank config PATCH call changed")

    expected_endpoints = {tuple(item) for item in inventory["endpoints"]}
    required_endpoints = {
        ("GET", "/health"),
        ("GET", "/version"),
        ("POST", "/v1/default/banks/{bank_id}/memories"),
        ("POST", "/v1/default/banks/{bank_id}/memories/recall"),
        ("PUT", "/v1/default/banks/{bank_id}"),
        ("PATCH", "/v1/default/banks/{bank_id}/config"),
        ("GET", "/v1/default/banks/{bank_id}/mental-models"),
        ("POST", "/v1/default/banks/{bank_id}/mental-models"),
        ("GET", "/v1/default/banks/{bank_id}/mental-models/{mental_model_id}"),
        ("PATCH", "/v1/default/banks/{bank_id}/mental-models/{mental_model_id}"),
        ("DELETE", "/v1/default/banks/{bank_id}/mental-models/{mental_model_id}"),
        ("POST", "/v1/default/banks/{bank_id}/reflect"),
    }
    if expected_endpoints != required_endpoints:
        raise SystemExit("compat/openclaw.json endpoint inventory changed without updating checker")

    print("OpenClaw compatibility inventory matches current upstream call surface")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
