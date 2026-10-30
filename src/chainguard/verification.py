"""Authorization-aware verification of signed delegation chains."""

from collections.abc import Sequence

from chainguard.core import Capability
from chainguard.identity import IdentityRegistry
from chainguard.integrity import SignedCapability, verify_signed_capability


def verify_capability_issuer(
    signed: SignedCapability,
    registry: IdentityRegistry,
) -> bool:
    """Verify that the registered key for capability.issuer signed it.

    This checks both signature authenticity and the binding between the
    claimed issuer identity and its trusted public key. It does not alone
    establish that the issuer was authorized to grant the requested scope.
    """
    if not isinstance(signed, SignedCapability):
        return False
    if not isinstance(registry, IdentityRegistry):
        return False

    trusted_key = registry.get_public_key(signed.capability.issuer)
    if trusted_key is None:
        return False

    return verify_signed_capability(signed, trusted_key)


def verify_delegation_chain(
    chain: Sequence[SignedCapability],
    registry: IdentityRegistry,
) -> bool:
    """Verify signatures, issuer relationships, lineage, and scope attenuation.

    The chain must be ordered from the human-issued root capability to the
    final delegated capability. Every capability must be signed by the
    registered key for its claimed issuer.
    """
    if not isinstance(registry, IdentityRegistry):
        return False
    if not isinstance(chain, (list, tuple)) or not chain:
        return False

    capabilities: list[Capability] = []
    for signed in chain:
        if not verify_capability_issuer(signed, registry):
            return False
        capabilities.append(signed.capability)

    root = capabilities[0]
    if root.parent_id is not None or root.ancestor_ids != ():
        return False
    if root.issuer != root.root_principal:
        return False

    for index in range(1, len(capabilities)):
        parent = capabilities[index - 1]
        child = capabilities[index]
        expected_ancestors = tuple(
            capability.capability_id for capability in capabilities[:index]
        )

        if child.parent_id != parent.capability_id:
            return False
        if child.ancestor_ids != expected_ancestors:
            return False
        if child.issuer != parent.subject:
            return False
        if child.root_principal != root.root_principal:
            return False
        if not child.actions.issubset(parent.actions):
            return False
        if not child.resources.issubset(parent.resources):
            return False

    return True
