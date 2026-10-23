# Integration contract

[Documentation](../../docs/README.md) | [Repository](../../README.md)

The PR quality gate checks the router endpoints and workflows that clients can observe.

- Fake Hindsight runs the same router workflow suite against SQLite and PostgreSQL quarantine storage.
- Real Hindsight runs the same router workflow suite against SQLite and PostgreSQL quarantine storage while Hindsight stays on PostgreSQL.
- SQLite and PostgreSQL router storage must produce the same observable quarantine and admin behavior.
  The SQLite path also examines mounted database persistence across router container recreation.
- For each new endpoint, route action, or externally observable workflow change, add or update integration coverage in `smoke.sh`.
  Update the contract manifest in `tests/test_integration_contract.py`.

The contract test fails intentionally when the routes of the router change without an explicit update of the integration tests.

The real-Hindsight recall smoke test retains a unique `CI_SMOKE_*` marker.
It waits at most 120 seconds for the marker to appear in recalled memory text.
The test retries empty healthy results while extraction runs.
Partial responses, failed banks, malformed results, and HTTP failures fail the check.
The deterministic LLM fixture extracts the marker only when it occurs in the retain request.


