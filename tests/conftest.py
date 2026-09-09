from __future__ import annotations

import logging

import pytest

import memory_router.app as app_module
import memory_router.logging as logging_module
import memory_router.openclaw as openclaw_module
from memory_router import probes


@pytest.fixture(autouse=True)
def reset_observability_state(caplog: pytest.LogCaptureFixture) -> None:
    openclaw_module.start_facade_scan_executor()
    previous_runtime = vars(app_module.runtime).copy()
    previous_admin_tokens = dict(app_module.runtime.admin_tokens)
    app_module.runtime.auth_prefilter = app_module.InMemoryRateLimiter()
    application_logger = logging.getLogger("memory_router")
    application_logger.addHandler(caplog.handler)
    logging_module.reset_log_state()
    probes.readiness_log_state = probes.ReadinessLogState()
    probes.storage_readiness_log_state = probes.ReadinessLogState(
        "storage_readiness_failed", "storage_readiness_recovered", "storage_health"
    )
    probes.readiness.cache = None
    probes.readiness.lock = None
    probes.version.cache = None
    probes.version.lock = None
    yield
    vars(app_module.runtime).clear()
    vars(app_module.runtime).update(previous_runtime)
    app_module.runtime.admin_tokens = previous_admin_tokens
    logging_module.reset_log_state()
    application_logger.removeHandler(caplog.handler)
