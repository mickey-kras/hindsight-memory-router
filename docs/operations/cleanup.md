# Quarantine cleanup

[Documentation](../README.md) | [Repository](../../README.md)

Use the scoped cleanup token for preview and execution.

`older_than` selects items created strictly before that instant.
Supply an ISO date-time with seconds and an explicit timezone (`Z` or `+/-HH:MM`), as in the examples below.
Timezone offsets for the same instant select the same items.
The endpoint accepts fractional seconds, including precision finer than the stored UTC milliseconds.
It excludes an item exactly at the cutoff.
Invalid, timezone-less, or out-of-range timestamps return `400`.

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

Cleanup returns `409` if the selected set changes after preview.
`QUARANTINE_EVENT_RETENTION_DAYS` controls event retention separately.
Set `QUARANTINE_EVENT_EXPORT_PATH` to append expired events to a JSONL file before pruning deletes them.
Each batch contains at most 1000 events.
A worker thread completes the append and file close before any deletion.

Cancellation during export, including shutdown, waits for the worker.
The batch then rolls back and releases its database transaction.
Slow export storage does not block the event loop.
It keeps the transaction open and can delay shutdown.

Export includes completed records at least once.
A failed append, cancellation, or database failure after append leaves the current batch's database rows available for retry.
Retrying can append duplicate records.
Deduplicate by `event_id`.
If a later batch fails, earlier successful batches stay committed.
The router records the `retention_pruned` summary separately after all batches succeed.

The file append and database commit are not atomic.
Export does not use `fsync` or guarantee crash durability.
A write failure can leave a partial final JSONL record.
Inspect that record before an operational retry.
Repair it before you retry.
A failed batch does not delete its selected events.

