from __future__ import annotations

import ast
from pathlib import Path

APP_PATH = Path("memory_router/app.py")
SMOKE_PATH = Path("tests/integration/smoke.sh")

EXPECTED_EXACT_PATHS = {
    "/admin/quarantine/cleanup",
    "/admin/quarantine/queue",
    "/admin/quarantine/stats",
    "/version",
}
EXPECTED_REGEX_PATHS = {
    r"/admin/quarantine/items/([^/]+)(?:/(approve|reject|postpone))?",
    r"/v1/default/banks/([^/]+)/memories(?:/(recall))?",
}
EXPECTED_DECORATED_PATHS = {"/health", "/ready", "/{path:path}"}
REQUIRED_INTEGRATION_CHECKS = {
    "router readiness and internal Hindsight become reachable",
    "authentication and network boundaries hold",
    "scoped admin tokens enforce read review and cleanup boundaries",
    "known writer retain succeeds",
    "safe recall endpoint succeeds",
    "unknown writer is encrypted only in quarantine database",
    "admin queue and item expose metadata plus ciphertext only",
    "local decryption recovers exact original outside router",
    "unknown item can be rejected without a Hindsight write",
    "unknown-writer recall degrades to empty results and can be postponed",
    "exact unchanged suspicious retain can be approved",
    "altered approval is rejected by original hash",
    "unsupported router and admin endpoints fail closed",
    "recalled suspicious memory can be approved and remains allowed",
    "recalled suspicious memory stays blocked after reject and invalidates upstream",
    "bulk cleanup uses dry-run count confirmation",
}


def _string_arg(call: ast.Call) -> str | None:
    if not call.args:
        return None
    value = call.args[0]
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def test_router_route_surface_is_declared_by_integration_contract() -> None:
    source = APP_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    exact_paths: set[str] = set()
    regex_paths: set[str] = set()
    decorated_paths: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            left = node.left
            comparators = node.comparators
            if isinstance(left, ast.Name) and left.id == "pathname" and len(comparators) == 1:
                value = comparators[0]
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    exact_paths.add(value.value)
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.func.attr == "fullmatch"
            ):
                pattern = _string_arg(node)
                if pattern is not None:
                    regex_paths.add(pattern)
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "app" and node.func.attr in {"get", "api_route"}:
                    path = _string_arg(node)
                    if path is not None:
                        decorated_paths.add(path)

    assert exact_paths == EXPECTED_EXACT_PATHS
    assert regex_paths == EXPECTED_REGEX_PATHS
    assert decorated_paths == EXPECTED_DECORATED_PATHS


def test_every_declared_workflow_has_integration_smoke_coverage() -> None:
    smoke = SMOKE_PATH.read_text(encoding="utf-8")
    missing = sorted(check for check in REQUIRED_INTEGRATION_CHECKS if check not in smoke)
    assert missing == []
