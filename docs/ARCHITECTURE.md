# ChainGuard Architecture

**Status:** Incremental research prototype  
**Version:** 0.2

## 1. Purpose

ChainGuard checks whether a multi-agent delegation chain grants an agent authority to perform a requested protected action.

The central rule is:

> An agent may delegate only authority it already has, and the protected tool must check that authority before acting.

## 2. Request flow

```text
Human
  |
  | creates a scoped root capability
  v
Agent A -- delegates a narrower capability --> Agent B
                                                |
                                                | submits signed chain + request
                                                v
                                       EnforcementGateway
                                        |      |      |
                                        |      |      +--> expiry / audience / workflow
                                        |      +---------> revocation / replay
                                        +----------------> identity / signatures / chain / scope
                                                |
                                      allow only if all checks pass
                                                |
                                                v
                                         ToolAdapter
                                                |
                                                v
                                         Protected service
```

The gateway and adapter are implemented as a local Python boundary. Deployment-level enforcement is not yet demonstrated. The protected service must not accept independent credentials from agents.

## 3. Components

### Capability model

A frozen capability records its unique ID, root principal, issuer, subject, action and resource scopes, parent ID, ancestor IDs, audience, workflow ID, and expiry.

### Delegation

A child capability inherits the parent's audience, workflow ID, and expiry. It may narrow action/resource scopes but cannot change the execution context or extend its lifetime.

### Cryptographic integrity

Ed25519 signs a deterministic representation of every authority-bearing field, including audience, workflow, and expiry.

### Identity registry

Maps principal identifiers to trusted public keys. It is currently in-memory and assumes authenticated enrollment happened outside this prototype.

### Chain verifier

Checks issuer signatures, parent-child relationships, exact ancestry, root continuity, scope attenuation, and context/expiry inheritance.

### Revocation registry

Revoking a capability invalidates that capability and descendants whose ancestry contains it. Current state is in-memory and process-local.

### Enforcement gateway

The gateway checks the complete chain and verifies an Ed25519-signed action request against the trusted key registered for the claimed actor. It then checks actor, action, resource, audience, workflow, expiry, and revocation state before invoking a tool adapter. It also consumes a unique request ID through a thread-safe, process-local replay guard.

The gateway consumes a request ID before calling the adapter. If the adapter fails after invocation, the ID remains consumed. This is an at-most-once attempt policy, not exactly-once delivery. External adapters need their own idempotency protocol for uncertain outcomes.

## 4. Fail-closed decision sequence

1. Validate request fields and adapter interface.
2. Verify every signed capability against the trusted issuer key.
3. Verify chain ordering, issuer relationships, ancestry, root continuity, and attenuation.
4. Verify the final subject matches the request actor.
5. Check action and resource scope.
6. Check signed audience and workflow binding.
7. Check expiry.
8. Check revocation closure.
9. Atomically consume the request ID within this process.
10. Invoke the adapter.

The adapter must execute exactly the action/resource represented by the authorized request. It must not reinterpret an authorized request as a broader operation.

## 5. Trust boundaries and deployment requirements

The local gateway is not enough if an agent can call the underlying service directly. A deployment must use gateway-held credentials, service-side authorization, network policy, or equivalent controls so the gateway is the only path.

The current replay guard is process-local. Multiple gateway instances do not share replay state. Revocation and execution are not one atomic transaction; a distributed production design must address races between revocation and execution.

## 6. Implementation status

| Capability | Status |
|---|---|
| Immutable capability and scope attenuation | Implemented |
| Ed25519 integrity | Implemented |
| In-memory trusted identity registry | Implemented |
| Delegation-chain verification | Implemented |
| In-memory ancestor-aware revocation | Implemented |
| Local fail-closed enforcement gateway | Implemented |
| Signed audience/workflow/expiry | Implemented |
| Process-local replay guard | Implemented |
| Durable/distributed identity and revocation | Planned |
| Shared replay/idempotency service | Planned |
| Production tool adapters and bypass controls | Planned |
| Structured audit events | Planned |
| Formal analysis and full benchmark | Planned |

## 7. Design principles

- Deny by default.
- Minimize trusted components.
- Keep policy decisions separate from tool execution.
- Validate untrusted inputs at boundaries.
- Use standard cryptographic primitives.
- Make decisions explainable and auditable.
- Keep the core framework-independent.
- State assumptions with every security claim.
