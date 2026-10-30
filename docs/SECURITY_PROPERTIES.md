# ChainGuard Security Properties

**Status:** Research specification  
**Version:** 0.1

This document defines the properties the implementation and evaluation are intended to test. A property is not considered achieved merely because it appears here.

## P1 — Scope attenuation

For parent capability P and child capability C:

- C.actions is a subset of P.actions.
- C.resources is a subset of P.resources.

A child must not acquire an action or resource that its parent does not possess.

**Falsification test:** construct a child with one extra action or resource and attempt to pass it through the protected-operation gateway. The operation must not execute.

## P2 — Issuer authenticity

A capability is accepted only if its signature verifies under the trusted public key registered for the capability's claimed issuer.

**Falsification test:** sign as one identity while claiming another issuer; alter a signed field; use an unregistered identity; substitute a public key.

## P3 — Delegation authorization

For each adjacent parent P and child C in a chain:
- C.issuer equals P.subject;
- C.parent_id equals P.capability_id;
- C.ancestor_ids exactly records the preceding capability IDs;
- C.root_principal equals the chain root;
- C's action and resource scopes are subsets of P's.

**Falsification test:** forge, reorder, omit, duplicate, or substitute chain elements and verify that protected execution is denied.

## P4 — Revocation closure

If capability P is revoked, P and every descendant of P are rejected. Revoking a child must not revoke its parent or unrelated siblings.

**Falsification test:** revoke a root, intermediate node, leaf, and sibling in separate trials; verify the expected impact on every related chain.

## P5 — Replay resistance

A request accepted once must not be accepted again when the operation semantics require single-use execution. Reuse must be rejected using a request identifier, nonce, expiry, or durable idempotency record.

**Falsification test:** submit the same signed request repeatedly, concurrently, and after expiry. Measure duplicate protected executions.

## P6 — Execution-context binding

Authority must be bound to the intended audience/tool and, where required, task or workflow. A capability for one service or task must not be usable against another.

**Falsification test:** reuse an otherwise valid capability with a different audience, tool, tenant, or workflow identifier.

## P7 — Enforcement completeness

Every protected operation must pass through the gateway. Agents must not possess independent credentials that permit bypass.

**Falsification test:** attempt direct invocation through every exposed tool/API path and inspect credential distribution and service-side authorization logs.

## P8 — Fail-closed behavior

Malformed proofs, unknown identities, unavailable mandatory trust/revocation state, invalid signatures, expired authority, and context mismatch must not result in protected execution.

**Falsification test:** inject each failure independently and during dependency outages; assert that the underlying operation was not called.

## P9 — Benign utility

Security controls should not reject valid operations or make normal workflows unusable beyond an explicitly measured overhead budget.

**Falsification test:** replay a fixed benign workload and report completion rate, false rejection rate, and latency with confidence intervals.

## Evidence levels

- **Specified:** written as a property.
- **Unit-tested:** tested in isolation.
- **Integration-tested:** tested across the gateway and its dependencies.
- **Adversarially evaluated:** tested against an explicit attack suite.
- **Formally analysed:** supported by a proof or model-checking result under stated assumptions.

Do not describe a property as guaranteed unless the evidence and assumptions justify that wording.
