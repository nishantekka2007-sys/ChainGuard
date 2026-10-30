# ChainGuard Architecture

**Status:** Target architecture; implementation is incremental  
**Version:** 0.1

## 1. What ChainGuard does

ChainGuard is an authorization layer for multi-agent systems. It lets a human grant an initial scope, lets agents delegate narrower scopes, and checks that authority before a protected tool or service performs an operation.

The central rule is simple:

> An agent may pass on only the authority it already has, and the protected tool must verify that authority before acting.

## 2. High-level flow

```text
Human
  |
  | grants root authority
  v
Root capability
  |
  v
Agent A -- delegates narrower authority --> Agent B
  |                                          |
  |                                          v
  +------------------------------------> Agent C
                                             |
                                             | requests a protected action
                                             v
                                      ChainGuard Gateway
                                       |   |   |   |
                                       |   |   |   +--> Context / replay checks
                                       |   |   +------> Revocation state
                                       |   +----------> Trusted identity keys
                                       +--------------> Chain + scope verification
                                             |
                                   allow only if every check passes
                                             |
                                             v
                                      Protected tool/API
```

The diagram describes the target architecture, not the current implementation.

## 3. Components

### Capability model
Represents the root principal, issuer, subject, allowed actions/resources, parent ID, and ancestry.

### Delegation
Creates a child capability whose action and resource scopes are subsets of the parent's.

### Cryptographic integrity
Uses Ed25519 to sign a deterministic representation of authority-bearing capability fields.

### Identity registry
Resolves principal IDs to trusted public keys. The current implementation is in-memory and assumes trusted enrollment.

### Chain verifier
Checks signatures and the authorization relationship between every parent and child in a root-to-leaf chain.

### Revocation service
Tracks revoked capability IDs and invalidates descendants. The current implementation is in-memory and process-local.

### Enforcement gateway — planned
The only permitted path to protected tools. It will validate identity, chain, scope, context, replay state, and revocation before invoking an adapter.

### Audit and experiment layer — planned
Produces structured, privacy-conscious decision records and repeatable evaluation output.

## 4. Request decision sequence

A protected request should be denied unless all required checks pass:

1. Parse and validate the request and proof structure.
2. Resolve the intended audience/tool and operation.
3. Load trusted issuer keys.
4. Verify every capability signature.
5. Verify the complete delegation chain and attenuation.
6. Verify expiry and execution context.
7. Check replay/idempotency state.
8. Check revocation state.
9. Apply the final action/resource policy.
10. Invoke the protected adapter.
11. Record the decision and outcome without logging secrets.

The implementation must define the ordering and atomicity of replay, revocation, and execution checks to avoid time-of-check/time-of-use gaps.

## 5. Security boundary

The gateway is effective only if the protected service cannot be called around it. The deployment must use gateway-held credentials, service-side network restrictions, or equivalent controls. Hiding a direct API key in agent prompts or configuration is not enforcement.

## 6. Current versus planned

| Capability | Status |
|---|---|
| Immutable capability model | Implemented |
| Scope attenuation helper | Implemented |
| Ed25519 signing and verification | Implemented |
| In-memory identity registry | Implemented |
| Delegation-chain verification | Implemented |
| In-memory ancestor-aware revocation | Implemented |
| Runtime gateway and tool adapters | Planned |
| Persistent/distributed revocation | Planned |
| Expiry, nonce, replay protection | Planned |
| Audience/task context binding | Planned |
| Structured audit trail | Planned |
| Adversarial benchmark harness | Planned |

## 7. Design principles

- Deny by default.
- Minimize trusted components.
- Keep policy decisions separate from tool execution.
- Validate untrusted inputs at boundaries.
- Use standard cryptographic primitives; do not invent cryptography.
- Make security decisions explainable and auditable.
- Keep the core library small and framework-independent.
- Treat every guarantee as conditional on explicit assumptions.
