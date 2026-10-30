# Adversarial Authorization Test Lab

**Status:** Initial deterministic test suite  
**Scope:** Python-level capability verification and the local enforcement gateway

## Purpose

This lab converts the baseline threat model into executable negative tests. Each attack case must demonstrate two outcomes:

1. the gateway rejects the malformed, forged, altered, expired, revoked, or context-invalid input; and
2. the protected adapter receives no call.

A rejected request is not enough if a protected side effect has already occurred. The adapter-call assertion is therefore part of every applicable test.

## Current attack cases

| Attack class | Mutation or attacker action | Expected result |
|---|---|---|
| Request tampering | Change action after signing | Reject invalid request signature |
| Resource tampering | Change resource after signing | Reject invalid request signature |
| Signer substitution | Sign request with an unregistered attacker key | Reject actor proof |
| Signature corruption | Flip a bit in the request signature | Reject invalid signature |
| Capability tampering | Change child scope after capability signing | Reject delegation-chain verification |
| Chain reordering | Reverse root and child elements | Reject chain verification |
| Chain truncation | Remove the parent while requesting as the child | Reject actor/subject mismatch |
| Leaf revocation | Revoke the final capability | Reject inactive authority |
| Expiry boundary | Execute at exactly `expires_at` | Reject; expiry is exclusive |
| Malformed request | Supply an empty required field | Reject before adapter execution |
| Invalid adapter | Supply an object without callable `execute` | Reject before adapter execution |

## Running

The tests are part of the standard pytest suite:

```bash
pytest -q
```

CI runs the suite on Python 3.11, 3.12, and 3.13.

## Interpretation

A passing test means only that the current implementation rejected that specific constructed input in the tested configuration. It does not prove resistance to unknown attacks, side channels, compromised infrastructure, direct tool API access, or flaws in real-world adapters.

## Gaps for the next iterations

- Parent substitution and cross-root chain construction across multiple independently valid chains.
- Key compromise and rotation races while requests are in flight.
- Revocation races between the gateway check and an external side effect.
- Replay under concurrent processes and after database restore/rollback.
- SQLite corruption, permission loss, and fail-closed behavior across every storage operation.
- Direct invocation of a protected service without the gateway.
- Property-based generation and mutation fuzzing of capability and request structures.
- Differential comparison against simpler baselines (no enforcement, scope-only, signatures-only).

## Reporting rule

Record attack ID, preconditions, exact input mutation, expected invariant, observed result, adapter invocation count, runtime, software version, and any deviation. Report false rejections separately from successful attacks. Do not aggregate unit-test pass counts into a claim of universal security.
