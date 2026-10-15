# Quarantine cleanup

[Documentation](../README.md) | [Repository](../../README.md)

Use the scoped cleanup token for preview and execution.

`older_than` selects items created strictly before that instant. Supply an ISO date-time with seconds and an explicit timezone (`Z` or `+/-HH:MM`), such as the examples below. Equivalent timezone offsets select the same items. Fractional seconds are accepted, including precision finer than the stored UTC milliseconds; an item exactly at the cutoff is excluded. Invalid, timezone-less, or out-of-range timestamps return `400`.

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

Cleanup returns `409` if the selected set changes after preview. Event retention is controlled separately by `QUARANTINE_EVENT_RETENTION_DAYS`. Set `QUARANTINE_EVENT_EXPORT_PATH` to append expired events to a JSONL file before pruning deletes them. Each batch contains at most 1000 events and finishes its append and file close in a worker thread before any deletion. Cancellation during export, including shutdown, waits for the worker before rolling back the batch and releasing its database transaction. Slow export storage does not block the event loop, but keeps that transaction open and can delay shutdown.

Export is at least once for completed records: a failed append, cancellation, or a database failure after appending leaves the current batch's database rows available for retry. Retrying can append duplicate records; deduplicate by `event_id`. Earlier successful batches remain committed if a later batch fails, and the `retention_pruned` summary is recorded separately after all batches succeed.

The file append and database commit are not atomic, and the export does not use `fsync` or promise crash durability. A write failure can leave a partial final JSONL record; inspect and repair that tail before an operational retry. A failed batch does not delete its selected events.
