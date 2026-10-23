# Main failures

[Documentation](README.md) | [Repository](../README.md)

The failure reporter covers failed validation, publishing, Pages and branch-update jobs.
It reads completed job logs with `GITHUB_TOKEN`.
Reporting does not change failed gates to passed gates.

Each issue contains the failed job and step, the diagnostic excerpt, the commit, and links to the run and its retry.
The reporter separates explicit test failures by test.
Smoke assertions include backend, check and message.
The reporter groups other explicit errors only when the job, step and normalized diagnostics match.
It ignores timestamps and temporary paths but keeps HTTP status codes and assertion values.

Exit codes alone are insufficient.
Missing diagnostics create an issue scoped to that occurrence.

An exact match appends an occurrence and reopens a closed issue. Reprocessing the same occurrence
does nothing. Previous descriptions stay the same. The reporter does not use legacy step-only markers again.
SonarQube keeps its existing finding IDs. A successful finding sync prevents a duplicate gate issue.

Smoke tests dump Compose status and container logs before cleanup, including startup failures.
Canceled workflows stop their reports, even if another job failed before cancellation.
Canceled and skipped jobs never create issues or trigger log downloads. Failures, timeouts,
startup failures and action-required conclusions stay reportable on all other workflows.

If the reporting job itself fails, rerun it to recover the report. For a canceled workflow,
rerun validation to get a completed result. GitHub outages or unavailable issue-write
permissions make a manual recovery necessary.

