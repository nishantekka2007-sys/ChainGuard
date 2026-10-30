# ChainGuard

A research prototype investigating verifiable authority delegation in autonomous multi-agent systems.

## Research question

Can a system ensure that every action in a multi-agent delegation chain remains within the scope originally authorized by a human, even when a downstream agent is compromised?

## Security properties under development

**Scope attenuation:** a child agent must never receive more permissions than its parent possesses.

For a parent capability \(P\) and child capability \(C\):

- \(C.actions \subseteq P.actions\)
- \(C.resources \subseteq P.resources\)

**Ancestor-aware revocation:** revoking a capability invalidates that capability and every descendant in its recorded delegation chain.

**Capability integrity:** Ed25519 signatures detect changes to the signed capability fields. Verification also requires the caller to provide the expected trusted public key.

## Project status

Early research prototype. The repository is being developed in small, tested sets:

1. Project scaffold and development configuration
2. Authorization model and scope-attenuation tests
3. In-memory, ancestor-aware capability revocation
4. Ed25519 capability signing and tamper detection
5. Runtime action enforcement
6. Persistent revocation, replay resistance, execution-context binding, and threat simulations

## Cryptographic design and limitations

The current integrity layer signs a deterministic JSON representation of all authority-bearing capability fields, including the parent and ancestor identifiers. Ed25519 signing and verification use the Python `cryptography` package and the API documented by [PyCA cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).

A valid signature proves that the corresponding private key signed the payload. It does **not** prove that the key belongs to the claimed issuer. The caller must obtain the expected public key from a trusted identity/key registry. Key distribution, storage, rotation, delegation-chain signature verification, and production key protection are not yet implemented.

The revocation registry is in-memory and process-local. Capability objects and signatures are not yet integrated into a runtime action-enforcement boundary. This is a research prototype, not a production security control.

Do not use this prototype to protect real accounts, funds, credentials, or production systems. Never commit private keys, access tokens, or local environment files.

## Development

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -v
```
