# Legacy quarantine migration

[Documentation](../README.md) | [Repository](../../README.md)

You can import legacy filesystem quarantine data into the current database-backed quarantine.
Import does not change the source files.

```bash
private-key-command | memory-router-migrate-legacy-quarantine \
  --queue /path/to/review.jsonl \
  --objects /path/to/quarantine-objects \
  --database sqlite:/path/to/quarantine.db
```

From a source checkout, install the project first with `python -m pip install -e .`.

The migration command is idempotent. Examine the summary of the command before you remove legacy data.

Keep the private key outside the router runtime during migration, exactly as for normal quarantine review.

