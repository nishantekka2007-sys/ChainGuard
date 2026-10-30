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

**Capability integrity:** Ed25519 signatures detect changes to signed capability fields.

**Identity-bound authorization:** the claimed issuer must have a registered public key matching the signature, and each child capability must be authorized by the preceding parent in the chain.

## Project status

Early research prototype. The repository is being developed in small, tested sets:

1. Project scaffold and development configuration
2. Authorization model and scope-attenuation tests
3. In-memory, ancestor-aware capability revocation
4. Ed25519 capability signing and tamper detection
5. Trusted identity registry and authorization-aware chain verification
6. Runtime action enforcement
7. Persistent revocation, replay resistance, execution-context binding, and threat simulations

## Cryptographic and trust model

The integrity layer signs a deterministic representation of all authority-bearing capability fields. The identity registry maps principal identifiers to trusted Ed25519 public keys. Chain verification checks each signature against the key registered for the claimed issuer, then checks parent linkage, delegation ancestry, root-principal continuity, and action/resource scope attenuation.

This separates two properties:

- **Authenticity:** the registered key for the claimed issuer signed the capability.
- **Authorization:** the issuer is the preceding capability's subject, and the child scope is a subset of the parent's scope.

A valid signature alone does not establish authorization. The registry in this prototype is in-memory and assumes its enrollment data is already trusted. Authenticated enrollment, durable key storage, key rotation, distributed trust, and production key protection are not implemented.

The revocation registry is also in-memory and process-local. Runtime action enforcement has not yet been integrated. This is a research prototype, not a production security control.

Do not use this prototype to protect real accounts, funds, credentials, or production systems. Never commit private keys, access tokens, or local environment files.

## Development

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -v
```
