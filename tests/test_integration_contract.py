from __future__ import annotations

import ast
import hashlib
import os
import subprocess
from pathlib import Path

APP_PATH = Path("memory_router/app.py")
POLICY_PATH = Path("memory_router/policy.py")
ADMIN_PATH = Path("memory_router/admin.py")
SMOKE_PATH = Path("tests/integration/smoke.sh")

HTTP_DECORATOR_METHODS = {
    "delete": "DELETE",
    "get": "GET",
    "head": "HEAD",
    "options": "OPTIONS",
    "patch": "PATCH",
    "post": "POST",
    "put": "PUT",
    "trace": "TRACE",
}
CATCH_ALL_PATH = "/{path:path}"
EXPECTED_CATCH_ALL_METHODS = {
    "CONNECT",
    "DELETE",
    "GET",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
    "TRACE",
}
DIRECT_ROUTE_COVERAGE = {
    ("GET", "/health"): "router readiness and internal Hindsight become reachable",
    ("GET", "/ready"): "router readiness and internal Hindsight become reachable",
}
ADMIN_PREFIX = "pathname.startswith('/admin/')"
ADMIN_ITEM_REGEX = (
    "regex:/admin/quarantine/items/([^/]+)(?:/(approve|reject|postpone))?"
)
BANK_MEMORY_REGEX = "regex:/v1/default/banks/([^/]+)/memories(?:/(recall))?"
DISPATCH_BRANCH_COVERAGE = {
    frozenset(
        {ADMIN_PREFIX, "method=='GET'", "pathname=='/admin/quarantine/queue'"}
    ): "admin queue and item expose metadata plus ciphertext only",
    frozenset(
        {ADMIN_PREFIX, "method=='GET'", "pathname=='/admin/quarantine/stats'"}
    ): "unknown writer is encrypted only in quarantine database",
    frozenset(
        {ADMIN_PREFIX, "method=='POST'", "pathname=='/admin/quarantine/cleanup'"}
    ): "bulk cleanup uses dry-run count confirmation",
    frozenset(
        {ADMIN_PREFIX, ADMIN_ITEM_REGEX, "method=='GET'", "action is None"}
    ): "admin queue and item expose metadata plus ciphertext only",
    frozenset(
        {ADMIN_PREFIX, ADMIN_ITEM_REGEX, "method=='POST'", "action=='approve'"}
    ): "exact unchanged suspicious retain can be approved",
    frozenset(
        {ADMIN_PREFIX, ADMIN_ITEM_REGEX, "method=='POST'", "action=='reject'"}
    ): "unknown item can be rejected without a Hindsight write",
    frozenset(
        {ADMIN_PREFIX, ADMIN_ITEM_REGEX, "method=='POST'", "action=='postpone'"}
    ): "unknown-writer recall degrades to empty results and can be postponed",
    frozenset(
        {"method=='GET'", "pathname=='/version'"}
    ): "authentication and network boundaries hold",
    frozenset(
        {BANK_MEMORY_REGEX, "method=='POST'"}
    ): "known writer retain succeeds",
    frozenset(
        {BANK_MEMORY_REGEX, "method=='POST'", "action=='recall'"}
    ): "safe recall endpoint succeeds",
}
REQUIRED_WORKFLOW_CHECKS = {
    "scoped admin tokens enforce read review and cleanup boundaries",
    "local decryption recovers exact original outside router",
    "altered approval is rejected by original hash",
    "unsupported router and admin endpoints fail closed",
    "recalled suspicious memory can be approved and remains allowed",
    "recalled suspicious memory stays blocked after reject and invalidates upstream",
}
INTEGRATION_BEHAVIOR_PATHS = {APP_PATH, POLICY_PATH, ADMIN_PATH}
ROUTE_HANDLER_AST_SHA256 = "ebe4707e5bc285d354f7d8bf8fe2f020c3f1a2cb9b94699a7ab3eb10e39e6321"


def _string_arg(call: ast.Call) -> str | None:
    if not call.args:
        return None
    value = call.args[0]
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


def _http_decorator_methods(call: ast.Call) -> set[str] | None:
    if (
        not isinstance(call.func, ast.Attribute)
        or not isinstance(call.func.value, ast.Name)
        or call.func.value.id != "app"
    ):
        return None
    if call.func.attr in HTTP_DECORATOR_METHODS:
        return {HTTP_DECORATOR_METHODS[call.func.attr]}
    if call.func.attr == "api_route":
        for keyword in call.keywords:
            if keyword.arg != "methods":
                continue
            value = keyword.value
            if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                raise AssertionError("app.api_route methods must be a literal collection")
            methods = {
                item.value.upper()
                for item in value.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            }
            if len(methods) != len(value.elts):
                raise AssertionError("app.api_route methods must be string literals")
            return methods
        raise AssertionError("app.api_route must declare methods")
    if call.func.attr == "exception_handler":
        return None
    raise AssertionError(f"unrecognized app decorator: app.{call.func.attr}")


def _decorated_routes(tree: ast.AST) -> tuple[set[tuple[str, str]], set[str]]:
    direct_routes: set[tuple[str, str]] = set()
    catch_all_methods: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            methods = _http_decorator_methods(decorator)
            if methods is None:
                continue
            path = _string_arg(decorator)
            if path is None:
                raise AssertionError("HTTP route path must be a string literal")
            if path == CATCH_ALL_PATH:
                catch_all_methods.update(methods)
            else:
                direct_routes.update((method, path) for method in methods)
    return direct_routes, catch_all_methods


def _regex_assignment(statement: ast.stmt) -> str | None:
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
        or statement.targets[0].id != "match"
        or not isinstance(statement.value, ast.Call)
    ):
        return None
    call = statement.value
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "re"
        and call.func.attr == "fullmatch"
    ):
        return _string_arg(call)
    return None


def _condition_parts(node: ast.expr, match_pattern: str | None) -> set[str]:
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        parts: set[str] = set()
        for value in node.values:
            parts.update(_condition_parts(value, match_pattern))
        return parts
    if isinstance(node, ast.Name) and node.id == "match":
        return {f"regex:{match_pattern}" if match_pattern else "match"}
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pathname"
        and node.func.attr == "startswith"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return {f"pathname.startswith({node.args[0].value!r})"}
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


def _dispatch_branches(dispatch: ast.AsyncFunctionDef) -> set[frozenset[str]]:
    branches: set[frozenset[str]] = set()

    def walk(
        statements: list[ast.stmt],
        inherited: set[str],
        match_pattern: str | None,
    ) -> None:
        current_pattern = match_pattern
        for statement in statements:
            pattern = _regex_assignment(statement)
            if pattern is not None:
                current_pattern = pattern
                continue
            if not isinstance(statement, ast.If):
                continue
            own_parts = _condition_parts(statement.test, current_pattern)
            combined = inherited | own_parts
            has_method = any(part.startswith("method") for part in combined)
            own_route_selector = any(
                part.startswith(("pathname", "action", "regex:")) or part == "match"
                for part in own_parts
            )
            if has_method and own_route_selector:
                branches.add(frozenset(combined))
            walk(statement.body, combined, current_pattern)
            walk(statement.orelse, inherited, current_pattern)

    walk(dispatch.body, set(), None)
    return branches


def _route_handler_fingerprint(tree: ast.AST) -> str:
    route_functions: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(
            isinstance(decorator, ast.Call)
            and _http_decorator_methods(decorator) is not None
            for decorator in node.decorator_list
        ):
            route_functions.append(ast.dump(node, include_attributes=False))
    if not route_functions:
        raise AssertionError("no HTTP route handlers found")
    payload = "\n".join(sorted(route_functions))
    return hashlib.sha256(payload.encode()).hexdigest()


def _pr_changed_files() -> set[Path] | None:
    base_ref = os.environ.get("GITHUB_BASE_REF")
    if not base_ref:
        return None
    merge_base = subprocess.run(
        ["git", "merge-base", "HEAD", f"origin/{base_ref}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    changed = subprocess.run(
        ["git", "diff", "--name-only", merge_base, "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return {Path(path) for path in changed if path}


def test_direct_http_routes_are_bound_to_integration_coverage() -> None:
    tree = ast.parse(APP_PATH.read_text(encoding="utf-8"))
    direct_routes, catch_all_methods = _decorated_routes(tree)

    assert direct_routes == set(DIRECT_ROUTE_COVERAGE)
    assert catch_all_methods == EXPECTED_CATCH_ALL_METHODS


def test_dispatch_method_action_surface_is_bound_to_integration_coverage() -> None:
    tree = ast.parse(APP_PATH.read_text(encoding="utf-8"))
    branches = _dispatch_branches(_dispatch_function(tree))

    assert branches == set(DISPATCH_BRANCH_COVERAGE)


def test_route_handler_behavior_fingerprint_is_explicit() -> None:
    tree = ast.parse(APP_PATH.read_text(encoding="utf-8"))

    assert _route_handler_fingerprint(tree) == ROUTE_HANDLER_AST_SHA256


def test_behavior_changes_update_integration_smoke_in_pr_ci() -> None:
    changed_files = _pr_changed_files()
    if changed_files is None:
        return
    if changed_files & INTEGRATION_BEHAVIOR_PATHS:
        assert SMOKE_PATH in changed_files


def test_every_declared_operation_and_workflow_has_integration_smoke_coverage() -> None:
    smoke = SMOKE_PATH.read_text(encoding="utf-8")
    required_checks = (
        set(DIRECT_ROUTE_COVERAGE.values())
        | set(DISPATCH_BRANCH_COVERAGE.values())
        | REQUIRED_WORKFLOW_CHECKS
    )
    missing = sorted(
        check for check in required_checks if f'begin_check "{check}"' not in smoke
    )

    assert missing == []
