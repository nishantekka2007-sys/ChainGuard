# ChainGuard: Verifiable Authority Delegation for Multi-Agent Systems

## Abstract

Autonomous multi-agent workflows distribute tasks across agents that may delegate work and invoke external tools. This creates an authorization problem: a downstream agent may be compromised, a delegation chain may be forged or replayed, or a valid permission may be used outside its intended context. ChainGuard is a research prototype investigating whether cryptographically verifiable, attenuated delegation combined with enforcement at the protected-operation boundary can constrain the actions of compromised downstream agents.

The proposed system combines signed capabilities, trusted issuer identities, parent-child chain verification, revocation, execution-context binding, replay resistance, and a tool-enforcement gateway. The research will compare staged baselines and evaluate attack success, false rejection, benign task completion, latency, and revocation behavior. The work does not assume that signatures alone provide authorization, nor that a compromised agent can be made harmless when it retains legitimate permissions.

## Research question

Under a defined threat model, can a gateway-enforced, cryptographically verifiable delegation chain reduce unauthorized protected actions by compromised downstream agents while preserving acceptable benign task utility and operational overhead?

## Working hypothesis

When all protected operations are forced through a trusted enforcement gateway, binding each delegation to its issuer, parent capability, attenuated scope, and execution context will reduce unauthorized downstream actions compared with systems that rely on agent prompts, local scope checks, or signature verification alone.

This hypothesis is deliberately conditional. It does not claim protection against a compromised gateway, trust anchor, underlying service, or excessive root authorization.

## Proposed contributions

1. A small, explicit capability model for multi-hop agent delegation.
2. Authorization-aware chain verification that distinguishes signature authenticity from delegation authority.
3. Revocation semantics for a capability and its descendants.
4. A gateway design that checks authority at the actual protected-operation boundary.
5. A reproducible adversarial evaluation with security and utility metrics.

The novelty of these contributions must be assessed against capability systems, Macaroons, OAuth-style delegation, agent identity standards, and recent agent-security research before publication claims are made.

## Method

1. Specify the threat model, trust assumptions, and invariants.
2. Implement the enforcement gateway and required state services.
3. Build attack cases for escalation, forgery, tampering, substitution, replay, context confusion, revocation failure, and bypass.
4. Compare staged baselines:
   - no enforcement;
   - scope checks only;
   - signature checks only;
   - signature plus trusted identity;
   - full chain verification;
   - full gateway with revocation, replay, and context checks.
5. Run benign and adversarial workloads under documented configurations.
6. Report raw counts, rates, latency distributions, confidence intervals, and limitations.

## Primary metrics

- Unauthorized action acceptance rate.
- Attack success rate by category.
- False rejection rate for valid requests.
- Benign task completion rate.
- Authorization latency (median and tail percentiles).
- Revocation propagation delay.
- Duplicate execution rate under replay.
- Resource and storage overhead.

## Expected outcome

The desired outcome is not a claim of universal security. It is a reproducible demonstration of which attacks the system prevents, under which assumptions, at what operational cost, and where it fails.
