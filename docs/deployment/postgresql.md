# PostgreSQL deployment

PostgreSQL is an optional quarantine-storage override.

Set:

```text
QUARANTINE_DATABASE_URL=postgresql://user:password@database:5432/quarantine
```

`postgres://` is also accepted. Use a database/schema isolated from Hindsight application data.

On startup Memory Router connects, initializes/validates its schema, and fails closed if the database is unavailable or lacks required privileges.

PostgreSQL also provides shared rate-limit state used by router replicas. For multi-instance operation, see [clustered deployment](clustered.md).
