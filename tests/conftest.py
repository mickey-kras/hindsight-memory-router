from __future__ import annotations

import logging

import pytest

import memory_router.app as app_module
import memory_router.logging as logging_module


@pytest.fixture(autouse=True)
def reset_observability_state(caplog: pytest.LogCaptureFixture) -> None:
    previous_runtime = vars(app_module.runtime).copy()
    previous_admin_tokens = dict(app_module.runtime.admin_tokens)
    application_logger = logging.getLogger("memory_router")
    application_logger.addHandler(caplog.handler)
    logging_module.reset_log_state()
    app_module._readiness_log_state = app_module._ReadinessLogState()
    app_module._storage_readiness_log_state = app_module._ReadinessLogState(
        "storage_readiness_failed", "storage_readiness_recovered", "storage_health"
    )
    app_module._readiness_cache = None
    app_module._readiness_lock = None
    app_module._version_cache = None
    app_module._version_lock = None
    yield
    vars(app_module.runtime).clear()
    vars(app_module.runtime).update(previous_runtime)
    app_module.runtime.admin_tokens = previous_admin_tokens
    logging_module.reset_log_state()
    application_logger.removeHandler(caplog.handler)
