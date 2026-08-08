# Legacy quarantine migration

Legacy filesystem quarantine data can be imported into the current database-backed quarantine without modifying the source files.

```bash
private-key-command | memory-router-migrate-legacy-quarantine \
  --queue /path/to/review.jsonl \
  --objects /path/to/quarantine-objects \
  --database sqlite:/path/to/quarantine.db
```

From a source checkout, install the project first with `python -m pip install -e .`.

The migration command is idempotent. Verify its summary before removing any legacy data.

Keep the private key outside the router runtime during migration, exactly as for normal quarantine review.
