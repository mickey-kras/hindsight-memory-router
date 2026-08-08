# SQLite deployment

SQLite is the default quarantine database for single-node Memory Router deployments.

Default URL:

```text
sqlite:./data/quarantine.db
```

In the Docker image, the working directory is `/app`, so the default resolves to `/app/data/quarantine.db`. Compose mounts the persistent `memory-router-data` named volume at `/app/data`; the database and SQLite WAL sidecars therefore remain inside that volume.

Memory Router validates SQLite directory/file writability at startup and fails fast if the configured storage is not writable.

Use an explicit `sqlite:` URL only when you need a different location. SQLite is not exposed as a network service and does not require direct host access.
