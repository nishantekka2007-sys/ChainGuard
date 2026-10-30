# Reproducible Baseline Benchmark

**Status:** Initial synthetic microbenchmark  
**Version:** 1.0

## Purpose

The benchmark makes the experiment plan executable. It compares a fixed benign request and a fixed downstream privilege-escalation attack across progressively stronger authorization baselines.

It is intentionally small and transparent. It is a harness smoke test—not a representative workload, security proof, or production performance study.

## Run

From the repository root:

```bash
python -m research.benchmark --trials 100 --output benchmark-results.json
```

Use `--output -` to print JSON to standard output. The report records the benchmark identifier, trial count, baseline names, accepted/rejected counts, attack success rate, false rejection rate, benign completion rate, and median/p95/p99 decision latency.

## Scenarios

1. **benign_read:** a valid read request from a downstream agent within its delegated scope.
2. **downstream_scope_escalation:** a compromised delegating agent signs a child capability that adds `delete`, although the root authority granted only `read`. The downstream agent then signs a delete request.

The attack uses a legitimate registered issuer key. This is important: the case tests authorization semantics, not merely whether signatures are mathematically valid.

## Baselines

| Baseline | Policy |
|---|---|
| B0 — no enforcement | Accept every request |
| B1 — scope only | Check requested action/resource against the presented leaf capability |
| B2 — signature only | Verify the leaf capability signature against the issuer's registered key |
| B4 — full chain | Verify the complete signed chain and requested action/resource |
| B5 — full gateway | Run the actual ChainGuard gateway, including actor proof, context, expiry, revocation and replay checks |

B3 (signature plus trusted identity as a separately measured intermediate) is reserved for a later iteration. B4 and B5 intentionally differ: B4 isolates chain authorization; B5 measures the complete runtime gateway path.

## Expected result for this attack

- B0, B1 and B2 accept the escalated operation. A valid signature does not prove that the issuer had authority to delegate the extra action.
- B4 and B5 reject the operation because the child scope exceeds the root scope.
- All baselines accept the benign read.

If observed outcomes differ, treat that as a failed benchmark assertion and investigate before interpreting performance numbers.

## Metrics and interpretation

- **Attack success rate:** accepted unauthorized requests divided by attack attempts.
- **False rejection rate:** rejected valid requests divided by valid requests.
- **Benign completion rate:** accepted valid requests divided by valid requests.
- **Latency:** time spent in the baseline decision path; median, p95 and p99 are reported in milliseconds.

The benchmark uses a fixed synthetic case, freshly generated Ed25519 keys per benchmark run, and repeated local decisions. It does not include network latency, real tools, model inference, distributed state, production database contention, or a broad attack corpus. Results should not be generalized beyond this scenario.

## Reproducibility checklist for future studies

Record the commit SHA, Python and cryptography versions, host/OS/CPU, trial count, benchmark JSON, and exact command. Use multiple seeds and held-out attack cases before drawing broader conclusions. Keep raw results; do not report only averages.
