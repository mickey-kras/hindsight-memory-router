# PostgreSQL deployment

[Documentation](../README.md) | [Repository](../../README.md)

PostgreSQL is an optional quarantine-storage override.

Set:

```text
QUARANTINE_DATABASE_URL=postgresql://user:password@database:5432/quarantine
```

The router also accepts `postgres://`. Use a database or schema that is separate from the Hindsight application data.

At startup, Memory Router connects to PostgreSQL and initializes or validates its schema.
Startup fails closed if the database is unavailable or does not have the necessary privileges.

PostgreSQL also keeps the shared rate-limit state for router replicas. For multi-instance operation, see [clustered deployment](clustered.md).

