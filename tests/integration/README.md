# Integration contract

The PR quality gate covers the router's externally observable endpoint/workflow surface.

- Fake Hindsight runs the same router workflow suite against SQLite and PostgreSQL quarantine storage.
- Real Hindsight runs the same router workflow suite against SQLite and PostgreSQL quarantine storage while Hindsight itself remains on PostgreSQL.
- SQLite and PostgreSQL router storage must produce the same observable quarantine/admin behavior; the SQLite path also verifies mounted database persistence across router container recreation.
- Every new endpoint, route action, or externally observable workflow change must add or update integration coverage in `smoke.sh` and the contract manifest in `tests/test_integration_contract.py`.

The contract test intentionally fails when the router route surface changes without an explicit integration-test update.


Real-Hindsight recall smoke retains a unique `CI_SMOKE_*` marker and waits at most
120 seconds for it to appear in recalled memory text. Empty healthy results are
retried while extraction runs; partial responses, failed banks, malformed results,
and HTTP failures fail the check. The deterministic LLM fixture extracts that
marker only when it occurs in the retain request.
