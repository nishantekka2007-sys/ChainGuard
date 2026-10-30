# ChainGuard

[![Tests](https://github.com/nishantekka2007-sys/ChainGuard/actions/workflows/tests.yml/badge.svg)](https://github.com/nishantekka2007-sys/ChainGuard/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

**Verifiable authority delegation for multi-agent AI systems.**

ChainGuard is an open research prototype exploring how to keep delegated agent permissions within the authority originally granted by a human. It models delegation as a chain of cryptographically signed capabilities and is being developed toward enforcement at the actual tool-execution boundary.

> **In plain language:** an AI agent should not be able to give another agent more power than it has—and a tool should check that authority before it performs an action.

## Why this matters

Multi-agent systems divide work among agents and tools. When one downstream agent is compromised, poorly constrained delegation can let it request actions beyond the original authorization. A signature alone is not enough: it can show who signed a capability, but not whether that issuer was allowed to grant the requested permissions.

ChainGuard separates **who signed it** from **whether the delegation is authorized**.

## Research question

Can a gateway-enforced, cryptographically verifiable delegation chain reduce unauthorized protected actions by compromised downstream agents while preserving acceptable task utility and operational performance?

This is a research question—not a claim that ChainGuard already guarantees security in every environment.

## How it works

```text
Human grants initial authority
            |
            v
       Agent A
            |
     delegates a narrower scope
            v
       Agent B
            |
     delegates a narrower scope
            v
       Agent C
            |
      requests an action
            v
     ChainGuard Gateway
       |   |   |   |
       |   |   |   +-- context and replay checks
       |   |   +------ revocation check
       |   +---------- trusted issuer identity
       +-------------- signature, chain and scope checks
            |
       allow or deny
            |
            v
       Protected tool
```

The gateway is part of the target architecture. It is **not yet implemented**. The diagram must not be read as a claim that current releases already mediate real tool calls.

## Current implementation

| Component | Status |
|---|---|
| Immutable capability model | Implemented |
| Action and resource scope attenuation | Implemented |
| Ed25519 capability signing and verification | Implemented |
| In-memory identity-to-key registry | Implemented |
| Authorization-aware delegation-chain verification | Implemented |
| In-memory ancestor-aware revocation | Implemented |
| Runtime enforcement gateway | Planned |
| Persistent/distributed revocation | Planned |
| Expiry and replay protection | Planned |
| Audience and workflow-context binding | Planned |
| Structured audit trail | Planned |
| Adversarial benchmark suite | Planned |

## Security model

The current prototype checks:
- **Scope attenuation:** child actions and resources must be subsets of the parent's.
- **Signature integrity:** signed capability fields cannot be changed without invalidating the signature.
- **Issuer identity:** the signature must match the trusted key registered for the claimed issuer.
- **Delegation authorization:** each child must be issued by the previous capability's subject.
- **Lineage and root continuity:** parent IDs, ancestor IDs, and root principal must form a consistent chain.
- **Ancestor-aware revocation:** revoking a capability invalidates descendants that record it in their lineage.

A valid signature proves that a key signed a payload. It does not, by itself, prove that the signer was authorized to delegate the requested scope.

## Research and design documents

Start here if you want to understand the project in depth:

- [Architecture](docs/ARCHITECTURE.md) — components, request flow, and trust boundaries.
- [Threat model](docs/THREAT_MODEL.md) — attacker capabilities, assumptions, and out-of-scope cases.
- [Security properties](docs/SECURITY_PROPERTIES.md) — precise properties and how to falsify them.
- [Research proposal](docs/RESEARCH_PROPOSAL.md) — question, hypothesis, contributions, and method.
- [Experiment plan](docs/EXPERIMENT_PLAN.md) — baselines, attack suite, metrics, and controls.
- [Limitations](docs/LIMITATIONS.md) — current gaps, residual risks, and claim discipline.

## Quick start

Requirements: Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -v
```

## Security and responsible use

ChainGuard is an **early-stage research prototype**, not a production security product. The identity and revocation registries are currently in-memory. There is no runtime gateway, durable replay protection, distributed trust service, or production key management.

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

The package metadata currently declares the MIT License. A complete license file should be added after the project owner confirms the intended licensing terms.
