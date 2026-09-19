# Quarantine cleanup

Use the scoped cleanup token for preview and execution.

Preview example:

```json
{
  "scope": "pending",
  "reasons": ["unknown_writer"],
  "older_than": "2026-07-01T00:00:00Z",
  "dry_run": true
}
```

Execute with the count returned by the preview:

```json
{
  "scope": "pending",
  "reasons": ["unknown_writer"],
  "older_than": "2026-07-01T00:00:00Z",
  "dry_run": false,
  "expected_count": 42
}
```

Cleanup returns `409` if the selected set changes after preview. Event retention is controlled separately by `QUARANTINE_EVENT_RETENTION_DAYS`. Set `QUARANTINE_EVENT_EXPORT_PATH` to append expired events to a JSONL file before pruning deletes them; a failed export aborts the prune, so events are never deleted unexported.
