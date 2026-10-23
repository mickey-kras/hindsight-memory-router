# Architecture

[Documentation](README.md) | [Repository](../README.md)

See the [C4 architecture index](architecture/README.md). The canonical model is [`architecture/workspace.dsl`](architecture/workspace.dsl).

Production-readiness findings are separate, in [Production readiness](operations/production-readiness.md).

Optional human authentication uses native OIDC authorization code with PKCE and server-side identity mapping.
One-use login state and revocable one-hour sessions share the router database.
A shared policy generation rejects stale replicas.
Human credentials cannot authorize administration or bypass bank policy.

