# ChainGuard Limitations and Assumptions

This document is intentionally explicit. A security prototype is more credible when it states what it does not protect.

## Current implementation limitations

- The identity registry is in-memory and assumes trusted enrollment.
- The revocation registry is in-memory and process-local.
- There is no runtime gateway enforcing decisions before real tool execution.
- There is no persistent or distributed revocation consistency model.
- There is no capability expiry, nonce, request identifier, audience, tenant, or workflow binding.
- There is no durable replay/idempotency store.
- There is no key rotation, key deactivation, or production key-management integration.
- The implementation has not yet been formally verified.
- The current test suite is not a comprehensive adversarial benchmark.

## Security limits that remain even after planned work

- A compromised agent may misuse actions and resources it legitimately possesses.
- An overbroad human root grant remains overbroad unless separate policy limits root authority.
- A compromised gateway can authorize malicious operations.
- A compromised identity trust anchor can undermine issuer authentication.
- A compromised underlying service or host can bypass application-level assumptions.
- Direct tool credentials outside the gateway defeat enforcement completeness.
- Individually authorized data access can still create disclosure through aggregation or inference.
- Prompt injection is not directly prevented; the system aims to constrain downstream execution authority.

## Operational trade-offs

Fail-closed checks improve protection when trust or revocation state is unavailable, but reduce availability. Persistent and distributed revocation introduces consistency and latency trade-offs. Stronger context binding can reduce accidental reuse but requires careful lifecycle management for tasks and workflows.

## Claim discipline

Use language such as:
- "the prototype rejects the tested privilege-escalation cases";
- "the gateway enforces the specified policy under the stated trust assumptions";
- "the experiment observed no successful attacks in this test set."

Avoid unsupported language such as:
- "unhackable";
- "guaranteed secure in every environment";
- "prevents all prompt injection";
- "solves agent security";
- "number one in the world."

## Production readiness

Do not deploy the current prototype to protect real accounts, funds, secrets, or production systems. Production use would require independent security review, hardened identity and key management, durable revocation, secure deployment architecture, service-side bypass prevention, operational monitoring, incident response, and a formal risk assessment.
