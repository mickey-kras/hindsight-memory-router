# SQLite deployment

SQLite is the default quarantine database for single-node Memory Router deployments.

Default URL:

```text
sqlite:./data/quarantine.db
```

In the Docker image, the working directory is `/app`, so the default resolves to `/app/data/quarantine.db`. Compose mounts the persistent `memory-router-data` named volume at `/app/data`; the database and SQLite WAL sidecars therefore remain inside that volume.

## Upgrade from the former default path

The built-in default database URL changed from the host-specific path:

```text
sqlite:/volume1/reports/hindsight-quarantine/quarantine.db
```

to:

```text
sqlite:./data/quarantine.db
```

Deployments that relied on the former default must migrate deliberately before upgrading. Either keep the existing database location by setting `QUARANTINE_DATABASE_URL` explicitly, or move the existing database (including applicable SQLite sidecar state while the router is stopped) to the new persistent location before starting the upgraded router. Otherwise the new default can create a fresh empty quarantine database and make the previous review queue appear missing.

Memory Router validates SQLite directory/file writability at startup and fails fast if the configured storage is not writable. Embedded deployments that construct the server programmatically can opt out of startup storage validation with `validateStorage: false`.

Use an explicit `sqlite:` URL only when you need a different location. SQLite is not exposed as a network service and does not require direct host access.
