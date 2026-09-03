from __future__ import annotations

import ast
import hashlib
from pathlib import Path

APP_PATH = Path("memory_router/app.py")
POLICY_PATH = Path("memory_router/policy.py")
ADMIN_PATH = Path("memory_router/admin.py")
AUTH_PATH = Path("memory_router/auth.py")
HINDSIGHT_PATH = Path("memory_router/hindsight.py")
LOGGING_PATH = Path("memory_router/logging.py")
LOGGING_CONTRACT_PATH = Path("memory_router/logging_contract.py")
OPENCLAW_PATH = Path("memory_router/openclaw.py")
FACADE_ROUTES_PATH = Path("memory_router/facade_routes.py")
SECURITY_PATH = Path("memory_router/security.py")
SCAN_WINDOWS_PATH = Path("memory_router/scan_windows.py")
UNICODE_SECURITY_PATH = Path("memory_router/unicode_security.py")
SMOKE_PATH = Path("tests/integration/smoke.sh")
DEFAULT_COMPOSE_SMOKE_PATH = Path("tests/integration/default-compose-smoke.sh")
OPENCLAW_SMOKE_PATH = Path("tests/integration/openclaw-compat.sh")

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
    ("GET", "/health/live"): "router liveness is dependency independent",
    ("GET", "/health/ready"): "router readiness and internal Hindsight become reachable",
    ("GET", "/ready"): "router readiness and internal Hindsight become reachable",
}
ADMIN_PREFIX = "pathname.startswith('/admin/')"
ADMIN_ITEM_REGEX = "regex:/admin/quarantine/items/([^/]+)(?:/(approve|reject|postpone))?"
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
        {"method=='GET'", "pathname=='/v1/default/banks'"}
    ): "per-agent principal grants are enforced",
    frozenset({BANK_MEMORY_REGEX, "method=='POST'"}): "known writer retain succeeds",
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
    "OpenClaw auto-retain and document ingest shapes succeed",
    "OpenClaw split payloads are blocked across retain items",
    "OpenClaw auto-recall and knowledge recall shapes succeed",
    "OpenClaw conditional requests reject nested injection before Hindsight",
    "Extended Hindsight facade endpoints resolve through writer bank",
    "Denied Hindsight surfaces fail closed at the router",
}
INTEGRATION_BEHAVIOR_PATHS = {
    path
    for path in Path("memory_router").rglob("*")
    if path.is_file() and path.suffix in {".py", ".json"}
}
INTEGRATION_BEHAVIOR_MARKER_PREFIX = "# integration-behavior-sha256: "


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


def _regex_assignment(statement: ast.stmt) -> tuple[str, str] | None:
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
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
        pattern = _string_arg(call)
        if pattern is not None:
            return statement.targets[0].id, pattern
    return None


def _literal_string_set(value: ast.expr) -> set[str] | None:
    if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return None
    items = {
        item.value
        for item in value.elts
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }
    return items if len(items) == len(value.elts) else None


def _condition_parts(node: ast.expr, patterns: dict[str, str]) -> set[str]:
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        parts: set[str] = set()
        for value in node.values:
            parts.update(_condition_parts(value, patterns))
        return parts
    if isinstance(node, ast.Name) and node.id in patterns:
        return {f"regex:{patterns[node.id]}"}
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
    ):
        operator = node.ops[0]
        comparator = node.comparators[0]
        if isinstance(operator, ast.In):
            values = _literal_string_set(comparator)
            if values is None:
                return set()
            rendered = ",".join(repr(value) for value in sorted(values))
            return {f"{node.left.id} in {{{rendered}}}"}
        if not isinstance(comparator, ast.Constant):
            return set()
        if isinstance(operator, ast.Eq):
            op = "=="
        elif isinstance(operator, ast.Is):
            op = " is "
        else:
            return set()
        return {f"{node.left.id}{op}{comparator.value!r}"}
    return set()


def _dispatch_function(tree: ast.AST) -> list[ast.AsyncFunctionDef]:
    # The dispatch surface spans dispatch and its extracted admin sub-handler.
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name in {"dispatch", "_dispatch_admin"}
    ]
    if len(functions) != 2:
        raise AssertionError("dispatch functions not found")
    return functions


def _dispatch_branches(dispatch: ast.AsyncFunctionDef) -> set[frozenset[str]]:
    branches: set[frozenset[str]] = set()

    def walk(
        statements: list[ast.stmt],
        inherited: set[str],
        patterns: dict[str, str],
    ) -> None:
        current_patterns = dict(patterns)
        for statement in statements:
            assignment = _regex_assignment(statement)
            if assignment is not None:
                name, pattern = assignment
                current_patterns[name] = pattern
                continue
            if not isinstance(statement, ast.If):
                continue
            own_parts = _condition_parts(statement.test, current_patterns)
            combined = inherited | own_parts
            has_method = any(part.startswith("method") for part in combined)
            own_route_selector = any(
                part.startswith(("pathname", "action", "regex:")) for part in own_parts
            )
            if has_method and own_route_selector:
                branches.add(frozenset(combined))
            walk(statement.body, combined, current_patterns)
            walk(statement.orelse, inherited, current_patterns)

    walk(dispatch.body, set(), {})
    return branches


def _git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _integration_behavior_fingerprint() -> str:
    parts = [
        f"{path.as_posix()}:{_git_blob_sha(path)}"
        for path in sorted(INTEGRATION_BEHAVIOR_PATHS, key=lambda value: value.as_posix())
    ]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def test_direct_http_routes_are_bound_to_integration_coverage() -> None:
    tree = ast.parse(APP_PATH.read_text(encoding="utf-8"))
    direct_routes, catch_all_methods = _decorated_routes(tree)

    assert direct_routes == set(DIRECT_ROUTE_COVERAGE)
    assert catch_all_methods == EXPECTED_CATCH_ALL_METHODS


def test_dispatch_method_action_surface_is_bound_to_integration_coverage() -> None:
    tree = ast.parse(APP_PATH.read_text(encoding="utf-8"))
    branches: set[frozenset[str]] = set()
    for dispatch_function in _dispatch_function(tree):
        branches |= _dispatch_branches(dispatch_function)

    assert branches == set(DISPATCH_BRANCH_COVERAGE)


def test_behavior_changes_require_integration_smoke_update() -> None:
    marker = f"{INTEGRATION_BEHAVIOR_MARKER_PREFIX}{_integration_behavior_fingerprint()}"
    smoke_lines = (
        SMOKE_PATH.read_text(encoding="utf-8") + OPENCLAW_SMOKE_PATH.read_text(encoding="utf-8")
    ).splitlines()

    assert marker in smoke_lines


def test_compose_wait_replaces_only_full_stack_readiness_polling() -> None:
    smoke = SMOKE_PATH.read_text(encoding="utf-8")
    default_smoke = DEFAULT_COMPOSE_SMOKE_PATH.read_text(encoding="utf-8")
    startup_checks = smoke.split('run_check "start compose stack"', 1)[1].split(
        'begin_check "authentication and network boundaries hold"', 1
    )[0]

    assert "up --wait --wait-timeout 120" in smoke
    assert "for _ in" not in startup_checks
    assert 'live_response="$(curl --max-time 5 -fsS "${router_url}/health/live")"' in smoke
    assert "urllib.request.urlopen('http://hindsight:8888/health', timeout=2)" in smoke
    assert '"${compose[@]}" up -d --no-build' in default_smoke
    assert "wait_for_liveness" in default_smoke


def test_every_declared_operation_and_workflow_has_integration_smoke_coverage() -> None:
    smoke = SMOKE_PATH.read_text(encoding="utf-8") + OPENCLAW_SMOKE_PATH.read_text(encoding="utf-8")
    required_checks = (
        set(DIRECT_ROUTE_COVERAGE.values())
        | set(DISPATCH_BRANCH_COVERAGE.values())
        | REQUIRED_WORKFLOW_CHECKS
    )
    missing = sorted(check for check in required_checks if f'begin_check "{check}"' not in smoke)

    assert missing == []
