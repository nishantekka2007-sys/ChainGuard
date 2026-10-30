# ChainGuard

A research prototype investigating verifiable authority delegation in autonomous multi-agent systems.

## Research question

Can a system ensure that every action in a multi-agent delegation chain remains within the scope originally authorized by a human, even when a downstream agent is compromised?

## Initial security property

**Scope attenuation:** a child agent must never receive more permissions than its parent possesses.

For a parent capability \(P\) and child capability \(C\):

- \(C.actions \subseteq P.actions\)
- \(C.resources \subseteq P.resources\)

These are initial design invariants, not a claim that the system is already secure.

## Project status

Early research prototype. The repository will develop in small, tested sets:

1. Project scaffold and development configuration
2. Authorization model and scope-attenuation tests
3. Cryptographic capability integrity and delegation-chain binding
4. Runtime action enforcement
5. Revocation, replay resistance, and execution-context binding
6. Threat simulations and evaluation

## Scope and limitations

ChainGuard is an experimental security research project. Early prototypes are not production security controls. We will document assumptions, threat boundaries, limitations, and test results as the design evolves.

## Development

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -v
```

## Security

Do not use this prototype to protect real accounts, funds, credentials, or production systems. Do not commit secrets, private keys, access tokens, or local environment files.
