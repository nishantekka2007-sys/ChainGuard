# ChainGuard Experiment Plan

**Status:** Initial plan  
**Version:** 0.1

## 1. Evaluation questions

- Does complete chain verification prevent forged or escalated downstream authority?
- Does revoking an ancestor invalidate every descendant at the enforcement point?
- Do replay and context-binding controls stop reuse across requests, tools, and workflows?
- Can a compromised agent bypass the gateway?
- What is the cost in latency, false rejection, and benign task completion?

## 2. Baselines

| ID | Configuration | What it tests |
|---|---|---|
| B0 | No authorization enforcement | Unprotected reference baseline |
| B1 | Scope checks only | Value and limits of attenuation |
| B2 | Signature verification only | Authenticity without delegation authorization |
| B3 | Signature + trusted identity | Issuer authenticity |
| B4 | Full chain verification | Parent-child authority and lineage |
| B5 | Full gateway | Chain, context, replay, revocation, and execution boundary |

All baselines must use the same workload, attack inputs, hardware, and measurement procedure where possible.

## 3. Attack suite

| Attack | Adversary action | Expected secure outcome |
|---|---|---|
| Action escalation | Add an action not in parent scope | Deny; no tool execution |
| Resource escalation | Add an unauthorized resource | Deny; no tool execution |
| Issuer impersonation | Claim another principal as issuer | Deny |
| Signature tampering | Modify a signed field | Deny |
| Parent substitution | Replace parent or parent ID | Deny |
| Chain reordering | Reorder or omit chain elements | Deny |
| Descendant after revocation | Use a child after ancestor revocation | Deny |
| Replay | Resubmit a previously accepted request | Reject duplicate when single-use semantics apply |
| Audience confusion | Use a capability against another tool/service | Deny |
| Workflow confusion | Reuse authority in another task/workflow | Deny when task binding is required |
| Malformed input | Submit invalid types, missing fields, or oversized values | Deny safely |
| Gateway bypass | Call protected service without gateway | Service-side control must deny |

A test counts as prevented only if the protected operation did not execute.

## 4. Benign workload

Create a fixed set of legitimate multi-agent workflows with known expected outcomes. Include root-to-agent, one-hop, and multi-hop delegations; narrow and broad valid scopes; valid revocation transitions; and expected tool calls.

The benign workload must be versioned and identical across baselines.

## 5. Metrics

For N attack attempts:
- Attack success rate = successful unauthorized executions / N.
- Unauthorized action acceptance rate = unauthorized executions / all unauthorized requests.
- False rejection rate = valid requests denied / all valid requests.
- Benign completion rate = successfully completed benign workflows / all benign workflows.
- Replay duplicate rate = duplicate protected executions / replay attempts.

Latency must include the gateway's complete authorization path. Report median, p95, and p99, plus environment details. Measure revocation propagation from the committed revoke event to the first point at which every relevant enforcement instance rejects the capability.

## 6. Experimental controls

- Fix and publish software versions, runtime, hardware, configuration, and workload seed.
- Separate development tests from held-out adversarial tests.
- Repeat timing trials and report distributions rather than a single number.
- Keep raw machine-readable results and scripts in the repository.
- Record failed runs and exclusions with reasons.
- Do not treat unit-test pass counts as attack-prevention rates.
- Do not claim zero risk from a finite test suite.

## 7. Release gates

A security milestone is not complete until:
1. positive and negative tests exist;
2. integration tests verify that rejected operations never reach the tool adapter;
3. a bypass test exists;
4. CI passes;
5. documentation and limitations match the actual implementation.

## 8. Results template

For each experiment, record:
- experiment ID and date;
- commit SHA;
- threat-model version;
- baseline and configuration;
- attack or workload category;
- number of trials;
- raw successes and failures;
- rates and confidence intervals;
- latency distribution;
- unexpected behavior;
- interpretation and limitations.
