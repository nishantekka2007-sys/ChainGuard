# ChainGuard Security Properties

**Status:** Research specification and implementation tracker  
**Version:** 0.2

A property is not considered achieved merely because it appears here. Status labels describe the current prototype, not production assurance.

## P1 — Scope attenuation

For parent P and child C, C.actions and C.resources must be subsets of the corresponding parent scopes.

**Prototype status:** Implemented in delegation and chain verification; gateway checks the requested action and resource against the leaf scope.

**Falsification test:** attempt action or resource escalation and assert that the adapter is never called.

## P2 — Issuer authenticity

Every capability signature must verify under the trusted public key registered for its claimed issuer.

**Prototype status:** Implemented with Ed25519 and either an in-memory or SQLite-backed identity registry. SQLite identities support key rotation and deactivation.

**Falsification test:** claim another issuer, use an unknown issuer, substitute a key, or tamper with signed fields.

## P3 — Delegation authorization

For every adjacent parent P and child C:
- C.issuer equals P.subject;
- C.parent_id equals P.capability_id;
- C.ancestor_ids exactly records the preceding capability IDs;
- C.root_principal equals the root principal;
- child action/resource scopes are subsets of parent scopes.

**Prototype status:** Implemented in chain verification.

**Falsification test:** reorder, omit, duplicate, or substitute chain elements.

## P4 — Revocation closure

Revoking a capability must invalidate it and every descendant. Revoking a child must not revoke its parent or siblings.

**Prototype status:** Implemented in in-memory and SQLite-backed registries and checked by the gateway.

**Limitation:** SQLite provides single-host persistence only. Revocation checks and external execution are not one atomic transaction.

## P5 — Replay resistance

A request ID must not be accepted twice by gateway instances sharing the configured replay store.

**Prototype status:** Implemented with an in-memory guard or SQLite-backed durable single-host replay guard.

**Limitation:** no distributed multi-host consistency, TTL/retention policy, or exactly-once external execution.

**Falsification test:** submit duplicate IDs sequentially and concurrently; assert only one adapter invocation.

## P6 — Execution-context binding

Authority must be bound to an intended audience and workflow. Child capabilities must inherit these claims and may not change them.

**Prototype status:** Implemented; audience, workflow ID, and expiry are signed capability fields.

**Limitation:** no standardized tenant/service identity model or external audience registry yet.

**Falsification test:** change audience/workflow, tamper with signed claims, or attempt a child context change.

## P7 — Enforcement completeness

Every protected operation must pass through the gateway. Agents must not possess independent credentials that permit bypass.

**Prototype status:** Local adapter boundary exists.

**Limitation:** repository code cannot establish infrastructure-level exclusivity. A deployment must prove service-side and credential-level bypass resistance.

## P8 — Fail-closed behavior

Malformed proofs, unknown identities, invalid signatures, expired or revoked capabilities, context mismatch, and duplicate request IDs must not cause adapter execution.

**Prototype status:** Implemented for the local gateway checks.

**Limitation:** persistent SQLite failures must fail closed; distributed dependency outages and cross-host consistency are not yet evaluated.

## P9 — Benign utility

Security controls should preserve valid task execution with measurable overhead.

**Prototype status:** Not yet benchmarked.

**Falsification test:** run fixed benign workloads and report completion rate, false rejection, and latency distributions.

## Evidence levels

- **Specified:** written as a property.
- **Unit-tested:** tested in isolation.
- **Integration-tested:** tested across the gateway and adapter.
- **Adversarially evaluated:** tested against an explicit attack suite.
- **Formally analysed:** supported by proof or model checking under stated assumptions.

Do not describe a property as guaranteed unless evidence and assumptions justify that wording.


## P10 — Request proof of possession

A protected action request must be signed by the private key registered to the claimed actor. The signature covers the request ID, actor, action, resource, audience, and workflow ID.

**Prototype status:** Implemented in the local gateway using Ed25519 and the in-memory identity registry.

**Falsification test:** change any signed request field after signing, claim another actor, or sign with an unregistered key. The adapter must not be invoked.

**Limitation:** this proves possession of the registered signing key for the request. It does not protect a compromised agent that legitimately controls that key, nor does it replace transport security or secure key storage.


## P11 — Persistent state continuity

When SQLite mode is configured, registered public keys, revocation records, and consumed request IDs must remain effective after registry/gateway objects are recreated and must be shared by local processes using the same database file.

**Prototype status:** Implemented for single-host SQLite storage; restart and concurrent replay integration tests are included.

**Limitation:** not a distributed consistency guarantee. Database compromise or rollback can undermine the state assumptions.


## P12 — Identity key lifecycle

An identity's active public key can be explicitly rotated or deactivated. After rotation, signatures made with the previous key must fail verification against the current registry. After deactivation, the identity must no longer authenticate capabilities or action requests.

**Prototype status:** Implemented for the SQLite registry with transactional rotation, deactivation, and public-key rotation history.

**Falsification test:** verify an old signature before rotation, rotate to a new key, and confirm the old signature fails while a new signature succeeds; deactivate an identity and confirm its signatures fail.

**Limitation:** authenticated enrollment, production key custody, KMS/HSM integration, multi-party approval, and distributed key state are not implemented.
