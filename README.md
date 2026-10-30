# ChainGuard

A research prototype investigating verifiable authority delegation in autonomous multi-agent systems.

## Research question

Can a system ensure that every action in a multi-agent delegation chain remains within the scope originally authorized by a human, even when a downstream agent is compromised?

## Initial security properties

**Scope attenuation:** a child agent must never receive more permissions than its parent possesses.

For a parent capability \(P\) and child capability \(C\):

- \(C.actions \subseteq P.actions\)
- \(C.resources \subseteq P.resources\)

**Ancestor-aware revocation:** revoking a capability invalidates that capability and every descendant in its recorded delegation chain.

## Project status

Early research prototype. The repository is being developed in small, tested sets:

1. Project scaffold and development configuration
2. Authorization model and scope-attenuation tests
3. In-memory, ancestor-aware capability revocation
4. Cryptographic capability integrity and delegation-chain binding
5. Runtime action enforcement
6. Replay resistance, execution-context binding, and threat simulations

## Scope and limitations

ChainGuard is an experimental security research project. The current revocation registry is in-memory and process-local. It does not provide persistence, distributed consistency, authenticated revocation messages, or cryptographic protection. Capability objects are not yet tamper-resistant. These are explicit limitations, not solved properties.

Do not use this prototype to protect real accounts, funds, credentials, or production systems. Do not commit secrets, private keys, access tokens, or local environment files.

## Development

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -v
```
