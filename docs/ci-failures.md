# Main failures

The final publish job reports failed validation, publishing, Pages and branch-update jobs.
It reads completed job logs with `GITHUB_TOKEN`; reporting does not turn failed gates green.

Each issue contains the failed job/step, diagnostic excerpt, commit and run/attempt links.
Explicit test failures are split by test. Smoke assertions include backend, check and message.
Other explicit errors are grouped only when the job, step and normalized diagnostics match.
Timestamps and temporary paths are ignored; HTTP status codes and assertion values are retained.
Exit codes alone are insufficient: missing diagnostics create an issue scoped to that occurrence.

An exact match appends an occurrence and reopens a closed issue. Reprocessing the same occurrence
does nothing. Previous descriptions remain intact. Legacy step-only markers are not reused.
SonarQube keeps its existing finding IDs; successful finding sync avoids a duplicate gate issue.

Smoke tests dump Compose status and container logs before cleanup, including startup failures.
If the reporting job itself fails or the entire workflow is cancelled, rerun that job to recover
the report. GitHub outages or unavailable issue-write permissions require manual recovery.
