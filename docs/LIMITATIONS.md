# ChainGuard Limitations and Assumptions

This document is intentionally explicit. A security prototype is more credible when it states what it does not protect.

## Current implementation limitations

- The default identity registry is in-memory. A SQLite-backed persistent registry is available, but enrollment still assumes an external trusted process.
- The default revocation registry is in-memory. SQLite-backed revocation records persist across restarts and can be shared by local processes using one database file.
- The default replay guard is process-local. A SQLite-backed replay guard provides durable single-host state shared by processes using one database file; it is not a distributed multi-host service.
- Revocation is a point-in-time check. A controlled interleaving demonstrates that a capability can be revoked after `require_active()` returns but before the adapter is called, and the current gateway can still invoke that adapter. See [Revocation TOCTOU experiment](REVOCATION_TOCTOU.md).\n- Revocation checks and external tool execution are not one atomic transaction.
- The gateway is a local Python boundary; infrastructure-level exclusivity and bypass prevention are not established.
- The adapter contract receives a minimal action/resource request; real adapters must enforce exact operation semantics and safe parameter handling.
- No production key-management service, key rotation, or key deactivation exists.
- No durable audit trail or complete adversarial benchmark exists.
- The implementation has not been formally verified.

## Security limits

- A compromised agent may misuse actions and resources it legitimately possesses.
- An overbroad human root grant remains overbroad unless separate policy limits root authority.
- A compromised gateway can authorize malicious operations.
- A compromised identity trust anchor can undermine issuer authentication.
- A compromised underlying service or host can bypass application-level assumptions.
- Direct tool credentials outside the gateway defeat enforcement completeness.
- Individually authorized data access can still create disclosure through aggregation or inference.
- Prompt injection is not directly prevented; ChainGuard aims to constrain downstream execution authority.

## Operational trade-offs

Fail-closed checks improve protection when authorization state is unavailable, but reduce availability. Distributed revocation introduces consistency and latency trade-offs. Replay prevention requires durable retention and careful idempotency semantics in a multi-instance deployment.

The local gateway consumes a request ID before invoking an adapter. If the adapter fails after receiving the request, the ID remains consumed. This avoids blind duplicate attempts but cannot determine whether a remote side effect occurred. Exactly-once execution requires cooperation from the underlying service, usually through idempotency keys and transactional semantics.

## Claim discipline

Use precise language:
- "the prototype rejected the tested privilege-escalation requests";
- "the local gateway enforced the specified checks in the tested configuration";
- "the experiment observed no successful attacks in this finite test set."

Avoid unsupported language such as:
- "unhackable";
- "guaranteed secure in every environment";
- "prevents all prompt injection";
- "solves agent security";
- "number one in the world."

## Production readiness

Do not deploy the current prototype to protect real accounts, funds, secrets, or production systems. Production use requires independent security review, hardened identity and key management, durable distributed revocation and replay protection, service-side bypass prevention, robust adapters, operational monitoring, incident response, and a formal risk assessment.
