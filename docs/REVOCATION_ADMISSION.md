# Revocation Admission Semantics

**Selected contract:** admission ordering  
**Scope:** one host, one SQLite database file, all gateway instances and revocation writers cooperating with this store.

## Contract

A protected request is admitted at the commit of one SQLite BEGIN IMMEDIATE transaction that:

1. checks the complete capability lineage for revocation;
2. rejects if the leaf or any ancestor is revoked;
3. consumes the request ID in the same transaction.

The SQLite write transaction serializes this admission decision against revocation writes made through SQLiteRevocationRegistry using the same database. If revocation commits first, admission observes it and rejects. If admission commits first, the request is admitted and may proceed.

## Important limitation

This is **not dispatch-time fencing**. A request admitted before revocation may invoke its adapter or complete after the revoke commits. Revocation does not cancel work already admitted. The guarantee also depends on every gateway and revocation writer using the same local database file and on SQLite's supported local-filesystem locking behavior.

The coordinator does not make a remote side effect atomic with the database transaction. If the adapter's outcome is unknown, request IDs remain consumed; external idempotency is still required for safe retries.

## Tests

tests/test_admission.py deterministically tests:
- revocation committed before admission => rejected, adapter not invoked;
- revocation committed after admission but before adapter invocation => admitted operation proceeds;
- request ID consumption is atomic with admission;
- separate coordinator instances share replay/admission state.

## Deployment requirements

- Use one local SQLite database file shared by all gateway processes on the host.
- Route revocation writes through SQLiteRevocationRegistry on that same file.
- Do not use network filesystems or multi-host deployments as if they had been validated.
- Do not claim that a successful revoke cancels an already-admitted operation.
- For dispatch-time revocation, the protected service must validate a fencing token at the side-effect boundary; that is not implemented here.
