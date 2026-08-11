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
EXPECTED_DISPATCH_METHOD_BRANCHES = {
    frozenset({"method=='GET'", "pathname=='/admin/quarantine/queue'"}),
    frozenset({"method=='GET'", "pathname=='/admin/quarantine/stats'"}),
    frozenset({"method=='POST'", "pathname=='/admin/quarantine/cleanup'"}),
    frozenset({"action is None", "method=='GET'"}),
    frozenset({"action=='approve'", "method=='POST'"}),
    frozenset({"action=='reject'", "method=='POST'"}),
    frozenset({"action=='postpone'", "method=='POST'"}),
    frozenset({"method=='GET'", "pathname=='/version'"}),
    frozenset({"match", "method=='POST'"}),
}
OPERATION_COVERAGE = {
    "GET /health": "router readiness and internal Hindsight become reachable",
    "GET /ready": "router readiness and internal Hindsight become reachable",
    "GET /version": "authentication and network boundaries hold",
    "GET /admin/quarantine/queue": "admin queue and item expose metadata plus ciphertext only",
    "GET /admin/quarantine/stats": "unknown writer is encrypted only in quarantine database",
    "GET /admin/quarantine/items/:id": "admin queue and item expose metadata plus ciphertext only",
    "POST /admin/quarantine/items/:id/approve": "exact unchanged suspicious retain can be approved",
    "POST /admin/quarantine/items/:id/reject": (
        "unknown item can be rejected without a Hindsight write"
    ),
    "POST /admin/quarantine/items/:id/postpone": (
        "unknown-writer recall degrades to empty results and can be postponed"
    ),
    "POST /admin/quarantine/cleanup": "bulk cleanup uses dry-run count confirmation",
    "POST /v1/default/banks/:writer/memories": "known writer retain succeeds",
    "POST /v1/default/banks/:writer/memories/recall": "safe recall endpoint succeeds",
    "unsupported router/admin route": "unsupported router and admin endpoints fail closed",
}
REQUIRED_WORKFLOW_CHECKS = {
    "scoped admin tokens enforce read review and cleanup boundaries",
    "local decryption recovers exact original outside router",
    "altered approval is rejected by original hash",
    "recalled suspicious memory can be approved and remains allowed",
    "recalled suspicious memory stays blocked after reject and invalidates upstream",
}


def _string_arg(call: ast.Call) -> str | None:
    if not call.args:
        return None
    value = call.args[0]
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def _condition_parts(node: ast.expr) -> set[str]:
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        parts: set[str] = set()
        for value in node.values:
            parts.update(_condition_parts(value))
        return parts
    if isinstance(node, ast.Name) and node.id == "match":
        return {"match"}
    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and len(node.comparators) == 1
        and isinstance(node.left, ast.Name)
        and node.left.id in {"method", "pathname", "action"}
        and isinstance(node.comparators[0], ast.Constant)
    ):
        operator = node.ops[0]
        if isinstance(operator, ast.Eq):
            op = "=="
        elif isinstance(operator, ast.Is):
            op = " is "
        else:
            return set()
        return {f"{node.left.id}{op}{node.comparators[0].value!r}"}
    return set()


def _dispatch_function(tree: ast.AST) -> ast.AsyncFunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "dispatch":
            return node
    raise AssertionError("dispatch function not found")


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
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "app"
                and node.func.attr in {"get", "api_route"}
            ):
                path = _string_arg(node)
                if path is not None:
                    decorated_paths.add(path)

    assert exact_paths == EXPECTED_EXACT_PATHS
    assert regex_paths == EXPECTED_REGEX_PATHS
    assert decorated_paths == EXPECTED_DECORATED_PATHS


def test_dispatch_method_action_surface_is_declared_by_integration_contract() -> None:
    tree = ast.parse(APP_PATH.read_text(encoding="utf-8"))
    branches: set[frozenset[str]] = set()
    for node in ast.walk(_dispatch_function(tree)):
        if not isinstance(node, ast.If):
            continue
        parts = _condition_parts(node.test)
        has_method = any(part.startswith("method") for part in parts)
        has_route_selector = any(
            part == "match" or part.startswith("pathname") or part.startswith("action")
            for part in parts
        )
        if has_method and has_route_selector:
            branches.add(frozenset(parts))

    assert branches == EXPECTED_DISPATCH_METHOD_BRANCHES


def test_every_declared_operation_and_workflow_has_integration_smoke_coverage() -> None:
    smoke = SMOKE_PATH.read_text(encoding="utf-8")
    required_checks = set(OPERATION_COVERAGE.values()) | REQUIRED_WORKFLOW_CHECKS
    missing = sorted(check for check in required_checks if f'begin_check "{check}"' not in smoke)
    assert missing == []
