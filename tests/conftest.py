from __future__ import annotations

import hashlib
import json
import re
import sys
import types

# The execution sandbox used while drafting does not mirror PyPI. CI installs the
# pinned dependencies first; these narrow shims only let the same tests exercise
# the rest of the port locally when those third-party modules are absent.
try:
    import rfc8785  # noqa: F401
except ModuleNotFoundError:
    module = types.ModuleType("rfc8785")
    module.dumps = lambda value: json.dumps(  # type: ignore[attr-defined]
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    sys.modules["rfc8785"] = module

try:
    import psycopg  # noqa: F401
except ModuleNotFoundError:
    psycopg = types.ModuleType("psycopg")
    psycopg.AsyncConnection = object  # type: ignore[attr-defined]
    rows = types.ModuleType("psycopg.rows")
    rows.dict_row = object()
    pool = types.ModuleType("psycopg_pool")

    class MissingPool:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("PostgreSQL dependency unavailable in local sandbox")

    pool.AsyncConnectionPool = MissingPool
    sys.modules["psycopg"] = psycopg
    sys.modules["psycopg.rows"] = rows
    sys.modules["psycopg_pool"] = pool

try:
    import agent_memory_guard  # noqa: F401
except ModuleNotFoundError:
    root = types.ModuleType("agent_memory_guard")
    detectors = types.ModuleType("agent_memory_guard.detectors")

    class Result:
        def __init__(self, detector: str, matched: bool):
            self.detector = detector
            self.matched = matched

    class Detector:
        name = "detector"
        patterns: tuple[str, ...] = ()

        def inspect(self, key, value, *, operation):
            text = str(value)
            return Result(
                self.name,
                any(re.search(pattern, text, re.I | re.S) for pattern in self.patterns),
            )

    class PromptInjectionDetector(Detector):
        name = "prompt_injection"
        patterns = (r"ignore (?:all |any |the )?(?:previous|prior|above) instructions",)

    class SensitiveDataDetector(Detector):
        name = "sensitive_data"
        patterns = (r"ghp_[A-Za-z0-9]{36}", r"AKIA[0-9A-Z]{16}")

    class ToolAbuseDetector(Detector):
        name = "tool_abuse"
        patterns = (r"(?:bash|sh|cmd|powershell)\s+-c\s+", r'"tool_call".*"name".*"arguments"')

    class PrivilegeEscalationDetector(Detector):
        name = "privilege_escalation"
        patterns = (r"(?:role|access_level|permission_level)\s*[:=]\s*[\'\"]?(?:admin|root|superuser|owner|system|god)",)

    class ExcessiveAutonomyDetector(Detector):
        name = "excessive_autonomy"
        patterns = (r"(?:require_confirmation|confirm_before|ask_before)\s*[:=]\s*(?:false|never|none|0|disabled)",)

    for cls in (
        PromptInjectionDetector,
        SensitiveDataDetector,
        ToolAbuseDetector,
        PrivilegeEscalationDetector,
        ExcessiveAutonomyDetector,
    ):
        setattr(detectors, cls.__name__, cls)
    root.detectors = detectors  # type: ignore[attr-defined]
    sys.modules["agent_memory_guard"] = root
    sys.modules["agent_memory_guard.detectors"] = detectors
