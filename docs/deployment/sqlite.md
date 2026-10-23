# SQLite deployment

[Documentation](../README.md) | [Repository](../../README.md)

SQLite is the default quarantine database for single-node Memory Router deployments.

Default URL:

```text
sqlite:./data/quarantine.db
```

In the Docker image, the working directory is `/app`.
For this reason, the default URL resolves to `/app/data/quarantine.db`.
Compose mounts the persistent `memory-router-data` named volume at `/app/data`.
The database and SQLite WAL sidecars stay in that volume.

## Upgrade from the former default path

The built-in default database URL changed from a host-specific absolute path:

```text
sqlite:<legacy-host-path>/quarantine.db
```

to:

```text
sqlite:./data/quarantine.db
```

Deployments that used the former default must migrate before upgrading.
To keep the existing database location, set `QUARANTINE_DATABASE_URL` explicitly.
Alternatively, stop the router.
Move the existing database and applicable SQLite sidecar state to the new persistent location.
Start the upgraded router only after the move.

Without migration, the new default can create a new empty quarantine database.
The previous review queue can then appear missing.

Memory Router validates at startup that it can write to the SQLite directory and file.
Startup fails immediately if the configured storage is not writable.
Embedded deployments that construct the server programmatically can disable startup storage validation with `validateStorage: false`.

Use an explicit `sqlite:` URL only for a different location. SQLite is not a network service, and it does not use direct host access.

