# Revocation TOCTOU Experiment

**Status:** Deterministic reproduction of a known prototype limitation  
**Experiment ID:** `chainguard_revocation_toctou_v1`

## Question

Can a protected operation execute when its capability is revoked after the gateway's revocation check but before the adapter is invoked?

## Relevant execution order

The current gateway performs these operations in order:

1. Verify the signed request and delegation chain.
2. Check actor, action, resource, audience, workflow, and expiry.
3. Call `revocations.require_active(capability)`.
4. Consume the request ID through the replay guard.
5. Invoke `adapter.execute(request)`.

There is no lock or shared transaction spanning steps 3–5. The revocation registry can therefore change after the active check has returned.

## Method

Run:

```bash
python -m research.revocation_toctou
```

Or write JSON to a file:

```bash
python -m research.revocation_toctou --output revocation-toctou-results.json
```

The experiment compares two cases:

- **Revoked before check:** revoke the root capability before calling the gateway. The gateway should reject and the adapter call count should remain zero.
- **Revoked after check:** use a test replay guard that first consumes the request ID and then revokes the capability. The gateway calls the replay guard only after `require_active()` has returned. The experiment checks whether the adapter is nevertheless invoked.

This is a deterministic interleaving at a known call boundary. It avoids flaky timing-based thread races and makes the ordering reproducible.

## Expected observation in the current implementation

| Case | Gateway result | Adapter calls |
|---|---|---:|
| Revoked before active check | Rejected | 0 |
| Revoked after active check, before adapter | Execution proceeds | 1 |

The second result demonstrates that a revocation event can occur before adapter invocation without being observed by that in-flight gateway call.

## Interpretation

The prototype provides a point-in-time revocation check, not a guarantee that no operation can execute after a concurrent revocation event. This is a check/use gap (TOCTOU).

The result does **not** establish that every production deployment is exploitable, nor does it model distributed revocation propagation, remote services, scheduler behavior, or a compromised gateway. It demonstrates the behavior of this local gateway under the explicitly controlled interleaving.

## Candidate mitigations to evaluate

1. **Per-capability synchronization:** serialize revocation and authorization/dispatch within one process. This only works if every relevant operation shares the same synchronization domain.
2. **Transactional authorization state:** use a storage design that can atomically claim/authorize an operation against a revocation version. A database transaction alone cannot make an unrelated remote side effect atomic.
3. **Fencing/version tokens:** include a monotonically increasing revocation or authority epoch and require the protected service to reject stale epochs at execution time.
4. **Service-side authorization:** move the final check to the protected service, close to the side effect. This is the strongest practical boundary when the service can enforce it.
5. **Idempotency and outcome handling:** separately address uncertain remote outcomes; replay prevention does not make remote execution exactly-once.

No mitigation is implemented by this experiment. The required semantics must be selected before implementation; see [Revocation consistency contract](REVOCATION_CONSISTENCY.md) for admission ordering, dispatch ordering, and completion-barrier alternatives.

## Reproducibility and limitations

The script generates fresh Ed25519 keys for each run and uses a fixed clock and local in-memory registries. It reports a small JSON result. It is a deterministic regression/research demonstration, not a throughput benchmark, statistical race estimate, distributed-systems proof, or security certification.
