# Identity Key Lifecycle

ChainGuard uses registered Ed25519 public keys to authenticate capability issuers and action-request signers. The private key must remain with the identity owner.

## Current prototype behavior

The SQLite-backed `SQLiteIdentityRegistry` supports:

- `register(identity, public_key)`: register an identity once.
- `rotate_key(identity, new_public_key)`: atomically replace its active public key and record the previous/replacement public keys in the key-history table.
- `deactivate(identity)`: deactivate the identity so the registry no longer returns its public key.
- `get_public_key(identity)`: return only an active public key.

Key rotation immediately invalidates signatures made with the old key when checked against the current registry. Deactivation also causes issuer and request-signature checks to fail closed.

Example:

```python
registry.rotate_key("agent-7", replacement_public_key)
registry.deactivate("agent-7")
```

The rotation history contains public keys only. ChainGuard does not store private keys.

## Operational requirements

1. Enroll an identity only after authenticating the owner through a trusted out-of-band process.
2. Generate and store private keys in a protected key store or hardware-backed service.
3. Never commit private keys, seed phrases, API tokens, or private key backups.
4. On suspected compromise, deactivate the identity and revoke affected capabilities.
5. Rotate keys through an authenticated administrative workflow and verify the new public key out of band.
6. Preserve and protect the SQLite database and its backups; database rollback or tampering can undermine trust state.

## Important limitations

- This is not a production KMS, HSM integration, certificate authority, or authenticated enrollment protocol.
- Rotation invalidates old signatures for that identity; it does not transparently re-sign existing capabilities.
- Deactivation prevents future verification using the identity's key, but does not erase already copied public keys or private-key material.
- The registry is a single-host SQLite trust store, not a distributed identity service.
- No automated recovery, dual-control approval, or key-compromise incident workflow is implemented.

The identity registry is a trust anchor. A compromised or rolled-back registry can undermine issuer authenticity; deployments must protect it as security-critical state.
