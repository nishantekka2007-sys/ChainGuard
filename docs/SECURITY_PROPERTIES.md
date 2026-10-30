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

**Prototype status:** Implemented with Ed25519 and an in-memory identity registry.

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

**Prototype status:** Implemented in an in-memory registry and checked by the gateway.

**Limitation:** process-local state and non-atomic interaction with external execution.

## P5 — Replay resistance

A request ID must not be accepted twice by the same gateway process.

**Prototype status:** Implemented with a thread-safe, process-local replay guard.

**Limitation:** no shared state across processes/hosts, durable retention, TTL policy, or exactly-once external execution.

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

**Limitation:** outages of external distributed dependencies are not yet modeled because the prototype uses in-memory state.

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
