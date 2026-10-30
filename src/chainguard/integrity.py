"""Ed25519 integrity protection for ChainGuard capabilities.

A valid signature proves that the holder of a particular private key signed
the exact capability payload. It does not, by itself, prove that the key is
authorized to represent the capability issuer. Callers must supply a trusted
public key obtained from an authenticated identity/key registry.
"""

from dataclasses import dataclass
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from chainguard.core import AuthorizationError, Capability


@dataclass(frozen=True)
class SignedCapability:
    """A capability together with its Ed25519 signer and signature."""

    capability: Capability
    signer_public_key: bytes
    signature: bytes


def _canonical_payload(capability: Capability) -> bytes:
    """Encode every authority-bearing field in a deterministic format."""
    if not isinstance(capability, Capability):
        raise AuthorizationError("A valid capability is required.")

    payload = {
        "capability_id": capability.capability_id,
        "root_principal": capability.root_principal,
        "issuer": capability.issuer,
        "subject": capability.subject,
        "actions": sorted(capability.actions),
        "resources": sorted(capability.resources),
        "parent_id": capability.parent_id,
        "ancestor_ids": list(capability.ancestor_ids),
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _raw_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign_capability(
    capability: Capability,
    private_key: Ed25519PrivateKey,
) -> SignedCapability:
    """Sign the canonical representation of a capability."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise AuthorizationError("A valid Ed25519 private key is required.")

    payload = _canonical_payload(capability)
    public_key = private_key.public_key()
    return SignedCapability(
        capability=capability,
        signer_public_key=_raw_public_key(public_key),
        signature=private_key.sign(payload),
    )


def verify_signed_capability(
    signed: SignedCapability,
    trusted_public_key: bytes,
) -> bool:
    """Verify signature integrity and that the signer key is trusted.

    Returns False for invalid signatures, malformed records, or a signer key
    that does not match the caller-provided trusted key.
    """
    if not isinstance(signed, SignedCapability):
        return False
    if not isinstance(trusted_public_key, bytes):
        return False
    if signed.signer_public_key != trusted_public_key:
        return False

    try:
        public_key = Ed25519PublicKey.from_public_bytes(trusted_public_key)
        public_key.verify(signed.signature, _canonical_payload(signed.capability))
    except (InvalidSignature, ValueError, TypeError, AuthorizationError):
        return False

    return True
