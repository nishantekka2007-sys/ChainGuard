# Persistent State with SQLite

ChainGuard can use SQLite to persist trusted public keys, revoked capability IDs, and consumed request IDs across process restarts. An optional SQLite admission coordinator atomically checks revocation lineage and consumes a request ID in one write transaction.

This is a **single-host persistence option**, not a distributed authorization service.

## Install

SQLite is part of Python's standard library. No additional dependency is required.

## Configure the registries

```python
from chainguard.gateway import EnforcementGateway
from chainguard.storage import (
    SQLiteIdentityRegistry,
    SQLiteReplayGuard,
    SQLiteRevocationRegistry,
)

database = "var/chainguard/state.sqlite3"

identities = SQLiteIdentityRegistry(database)
revocations = SQLiteRevocationRegistry(database)
replay_guard = SQLiteReplayGuard(database)

gateway = EnforcementGateway(
    identities,
    revocations,
    replay_guard=replay_guard,
)
```

Register each principal's public key through an authenticated enrollment process before accepting its capabilities. The SQLite registry refuses to silently replace an identity's existing key.

For serialized admission, supply the same database path to the identity, revocation, and replay stores and to SQLiteAdmissionCoordinator. Use a local filesystem path accessible to the gateway process. Keep the database and its backups protected by operating-system permissions and operational controls.

## Serialized admission (optional)

Pass SQLiteAdmissionCoordinator(database) as the gateway's admission_coordinator argument. It uses BEGIN IMMEDIATE to serialize the revocation check and request-ID consumption against revocation writes on the same database. This defines admission ordering: an operation admitted before a later revoke may still execute or complete after the revoke. It does not provide dispatch-time fencing or cancellation. See [Revocation admission semantics](REVOCATION_ADMISSION.md).

## What persists?

| State | SQLite table | Behavior |
|---|---|---|
| Trusted public keys | `trusted_identities` | Identity registration survives restart; duplicate IDs are rejected |
| Revoked capability IDs | `revoked_capabilities` | Revocation survives restart and invalidates descendants |
| Consumed request IDs | `consumed_requests` | Duplicate IDs are rejected across gateway instances sharing the database |

## Failure behavior

The gateway must not call the adapter if a persistent store cannot provide the required state. Do not add a permissive in-memory fallback when SQLite is unavailable.

The replay guard consumes an ID before adapter invocation. If an external operation fails after it may have taken effect, the ID remains consumed. Exactly-once side effects require an idempotency protocol implemented by the external service.

## Explicit limitations

- SQLite is not a multi-host distributed database or consensus system.
- Network filesystem behavior is not validated.
- Revocation lookup and a remote side effect are not one atomic transaction.
- Database rollback or tampering can undermine revocation and replay guarantees.
- Private signing keys are not stored by ChainGuard; use an appropriate key-management system.
- Identity enrollment and key rotation are not implemented by this module.
- No claim of production readiness follows from the persistence tests.

## Tests

The test suite verifies persistence across registry/gateway reconstruction, ancestor revocation, duplicate replay rejection, and concurrent consumers using separate store instances.
