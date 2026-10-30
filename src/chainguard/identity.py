"""Trusted identity-to-public-key registry for ChainGuard."""

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from chainguard.core import AuthorizationError


@dataclass
class IdentityRegistry:
    """Map authenticated principal identifiers to trusted Ed25519 public keys.

    This in-memory registry is a prototype trust anchor. Production systems
    need authenticated enrollment, durable storage, key rotation, and
    revocation procedures.
    """

    _keys: dict[str, bytes] = field(default_factory=dict, repr=False)

    def register(self, identity: str, public_key: bytes) -> None:
        """Register an identity once; silently replacing a key is forbidden."""
        if not isinstance(identity, str) or not identity.strip():
            raise AuthorizationError("Identity must be a non-empty string.")
        if not isinstance(public_key, bytes):
            raise AuthorizationError("Public key must be raw Ed25519 bytes.")

        try:
            Ed25519PublicKey.from_public_bytes(public_key)
        except (ValueError, TypeError) as exc:
            raise AuthorizationError("Invalid Ed25519 public key.") from exc

        identity = identity.strip()
        if identity in self._keys:
            raise AuthorizationError("Identity is already registered.")

        self._keys[identity] = public_key

    def get_public_key(self, identity: str) -> bytes | None:
        """Return the trusted public key for an identity, if registered."""
        if not isinstance(identity, str):
            return None
        return self._keys.get(identity.strip())

    def is_registered(self, identity: str) -> bool:
        """Return whether an identity has a trusted public key."""
        return self.get_public_key(identity) is not None
