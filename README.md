# ChainGuard

[![Tests](https://github.com/nishantekka2007-sys/ChainGuard/actions/workflows/tests.yml/badge.svg)](https://github.com/nishantekka2007-sys/ChainGuard/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Security: research prototype](https://img.shields.io/badge/security-research%20prototype-orange)](docs/LIMITATIONS.md)

**Verifiable authority delegation for multi-agent AI systems.**

ChainGuard is an open research prototype exploring how to keep delegated agent permissions within the authority originally granted by a human. It combines signed capabilities, identity-bound delegation-chain verification, context restrictions, revocation checks, and a protected-operation gateway.

> **In plain language:** an AI agent should not be able to give another agent more power than it has—and a protected tool should check that authority before it performs an action.

## Why this matters

Multi-agent systems divide work among agents and tools. When a downstream agent is compromised, poorly constrained delegation can let it request actions beyond the original authorization. A signature alone is not enough: it can show who signed a capability, but not whether that issuer was allowed to grant the requested permissions.

ChainGuard separates **who signed it** from **whether the delegation is authorized**.

## Research question

Can a gateway-enforced, cryptographically verifiable delegation chain reduce unauthorized protected actions by compromised downstream agents while preserving acceptable task utility and operational performance?

This is a research question—not a claim that ChainGuard already guarantees security in every environment.

## How it works

```text
Human grants a scoped capability
              |
              v
          Agent A
              |
       delegates narrower scope
              v
          Agent B
              |
        requests an action
              v
       ChainGuard Gateway
        |      |       |
        |      |       +-- expiry, audience and workflow checks
        |      +---------- revocation and replay checks
        +----------------- signature, identity, chain and scope checks
              |
        allow only if all checks pass
              |
              v
        Protected tool adapter
```

The Python gateway now provides a local enforcement boundary for a supplied adapter. A real deployment must still ensure that the protected service cannot be called directly with agent-held credentials.

## Current implementation

| Component | Status |
|---|---|
| Immutable capability model | Implemented |
| Action and resource scope attenuation | Implemented |
| Ed25519 signing of authority and context fields | Implemented |
| In-memory identity-to-key registry | Implemented |
| Authorization-aware delegation-chain verification | Implemented |
| In-memory ancestor-aware revocation | Implemented |
| Gateway checks before adapter execution | Implemented |
| Audience, workflow and expiry binding | Implemented |
| Thread-safe, process-local replay guard | Implemented |
| Durable/distributed identity and revocation | Planned |
| Durable replay/idempotency and multi-instance consistency | Planned |
| Production tool adapters and infrastructure bypass prevention | Planned |
| Structured audit trail and adversarial benchmark | Planned |

## Security checks performed by the gateway

Before calling the adapter, the gateway verifies:
1. the complete signed delegation chain and the actor's signed proof of possession;
2. that the request actor is the final capability subject;
3. that the requested action and resource are within the final scope;
4. that audience and workflow match the signed capability context;
5. that the capability has not expired;
6. that the capability or any ancestor has not been revoked;
7. that the request ID has not already been consumed.

If a check fails, the adapter is not called. The gateway consumes the request ID before adapter invocation; if the adapter fails after receiving the request, that ID remains consumed to avoid accidental duplicate execution.

## Quick start

Requirements: Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -v
```

See [Architecture](docs/ARCHITECTURE.md) for the design and [Threat Model](docs/THREAT_MODEL.md) for assumptions. A runnable educational example is available at [examples/minimal_gateway.py](examples/minimal_gateway.py).

## Research and design documents

- [Architecture](docs/ARCHITECTURE.md) — components, request flow, and trust boundaries.
- [Threat model](docs/THREAT_MODEL.md) — attacker capabilities, assumptions, and out-of-scope cases.
- [Security properties](docs/SECURITY_PROPERTIES.md) — properties and falsification tests.
- [Research proposal](docs/RESEARCH_PROPOSAL.md) — question, hypothesis, contributions, and method.
- [Experiment plan](docs/EXPERIMENT_PLAN.md) — baselines, attack suite, metrics, and controls.
- [Limitations](docs/LIMITATIONS.md) — current gaps, residual risks, and claim discipline.

## Security and responsible use

ChainGuard remains an **early-stage research prototype**, not a production security product. Identity, revocation, and replay state are in-memory and process-local. There is no durable distributed consistency model, production key management, or proof that every deployment path is forced through the gateway.

Do not use this version to protect real accounts, funds, credentials, sensitive data, or production systems. Do not commit private keys, API tokens, or secrets. Security claims must always name the tested threat model and assumptions.

## Development principles

- Deny by default at protected-operation boundaries.
- Use established cryptographic primitives; do not invent cryptography.
- Keep the core small, modular, typed, and framework-independent.
- Test both allowed and forbidden behavior.
- Treat bypass tests as first-class security tests.
- Measure security and benign utility together.
- Document limitations as carefully as capabilities.

## License

MIT. See [LICENSE](LICENSE).
