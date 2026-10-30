# Revocation Consistency Contract

**Status:** Admission ordering selected and implemented as an optional single-host SQLite mode  
**Related experiment:** [Revocation TOCTOU](REVOCATION_TOCTOU.md)

## 1. Why this contract is necessary

The gateway currently checks revocation and later invokes an adapter. A revoke can commit between those events. The deterministic experiment demonstrates that the gateway may still invoke the adapter in that interleaving.

The phrase "revocation is immediate" is therefore too vague to be a testable security requirement. The system must define which event revocation orders against: request admission, side-effect dispatch, or side-effect completion.

## 2. Events and terminology

For one protected operation, distinguish these events:

- **Revoke commit (R):** the authoritative revocation state change has committed.
- **Authorization check (A):** the gateway reads revocation state and observes the capability as active.
- **Admission (D):** the gateway accepts the request for processing.
- **Side-effect start (S):** the protected service begins the externally visible operation.
- **Completion (C):** the protected service reports the operation complete.

These events are not interchangeable. In particular, adapter invocation is not necessarily the same as side-effect start or completion.

## 3. Candidate consistency contracts

### Contract A — Admission ordering

A request admitted before R may complete. A request admitted after R must be rejected, assuming it reads authoritative, sufficiently fresh revocation state.

This contract is implementable with a well-defined serialization point for admission and revocation. It does **not** promise that no side effect starts after R: a request admitted earlier may be queued and dispatched later.

### Contract B — Dispatch ordering

A protected service must reject an operation whose authorization epoch is older than the latest committed revocation epoch at the service's side-effect boundary. Thus, if R precedes S in the service's serialization order, the side effect must not start.

This requires the protected service (or a trusted enforcement component immediately controlling it) to validate a fencing/version token at the point where it can serialize that check against the side effect. A gateway-only lock or pre-dispatch database check cannot establish this across independent processes or remote services.

### Contract C — Completion barrier

After R returns successfully, no operation covered by that revocation may remain in flight or complete later.

This is stronger than dispatch ordering. It requires tracking and draining or cancelling already-started operations, plus defined behavior for irreversible external effects. It may be impossible for some tools and services. Do not claim it without service-specific cancellation and completion semantics.

## 4. Current prototype guarantee

The default gateway path provides a point-in-time check only. When SQLiteAdmissionCoordinator is configured with the same database used by revocation writers, admission and revocation are serialized under Contract A:

- If revocation commits before the admission transaction, the request is rejected.
- If admission commits first, the request may still reach the adapter or complete after a later revoke.
- SQLite persistence does not close this gap; a transaction in the revocation store cannot make an unrelated adapter side effect atomic.
- No distributed freshness, fencing, cancellation, or completion barrier is currently established.

The prototype has a tested single-host admission-ordering mode, but does not satisfy a dispatch-ordering guarantee or completion barrier under concurrent revocation.

## 5. Selected prototype contract: admission ordering

For the current research prototype, select Contract A (admission ordering) for the explicitly limited single-host SQLite deployment. Contract B and Contract C remain future research work. The deployment assumptions are:

| Question | Why it matters |
|---|---|
| Is an already-admitted request allowed to finish? | Separates admission ordering from stronger semantics |
| Must revocation prevent a side effect that has not started? | Requires dispatch-time serialization or service-side fencing |
| Must revocation wait for or cancel operations already started? | Requires completion tracking and possibly cancellation |
| Is the state single-process, single-host, or multi-host? | Determines whether local locks or SQLite can coordinate all actors |
| Can the protected service validate a token/epoch itself? | Determines whether enforcement can be placed at the actual side-effect boundary |
| What happens when the service is unavailable or its outcome is unknown? | Defines fail-closed behavior, retries, and idempotency |

The optional SQLiteAdmissionCoordinator implements Contract A by checking revocation lineage and consuming the request ID inside one BEGIN IMMEDIATE transaction. This is serialized against revocation writes using the same database. It does not establish Contract B or Contract C. Each stronger candidate still requires tests at the actual protected-service boundary.

## 6. Minimum falsification tests

For whichever contract is selected, add deterministic tests for:

1. Revoke commits before authorization check.
2. Revoke commits after authorization check but before admission completes.
3. Revoke commits after admission but before dispatch.
4. Revoke races with side-effect start at the protected service.
5. Revoke occurs after side-effect start but before completion.
6. Two gateway processes observe the same revocation state.
7. The revocation store or protected service is unavailable.
8. A retry follows an unknown or timed-out side-effect outcome.

Record R, A, D, S, and C ordering, whether the side effect began, whether it completed, and whether the caller received a definitive result. A denied gateway response alone is not sufficient evidence if the side effect may already have occurred.

## 7. Research boundary

This contract is a design and evaluation framework, not a claim that any candidate mechanism has been implemented or proven. Results must state the selected contract, deployment assumptions, service boundary, and tested failure modes.


## 8. Implementation reference

See [REVOCATION_ADMISSION.md](REVOCATION_ADMISSION.md) for the implemented SQLite admission contract, configuration requirements, and deterministic tests.


## 8. Implementation reference

See [REVOCATION_ADMISSION.md](REVOCATION_ADMISSION.md) for the implemented admission contract and its single-host constraints.
