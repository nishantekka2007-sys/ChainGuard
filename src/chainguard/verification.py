"""Authorization-aware verification of signed delegation chains."""

from collections.abc import Sequence

from chainguard.core import Capability
from chainguard.identity import IdentityRegistry
from chainguard.integrity import SignedCapability, verify_signed_capability


def _is_well_formed_capability(capability: object) -> bool:
    """Reject malformed capability structures before policy evaluation."""
    if not isinstance(capability, Capability):
        return False
    identity_fields = (
        capability.capability_id, capability.root_principal,
        capability.issuer, capability.subject,
    )
    if any(not isinstance(value, str) or not value.strip() for value in identity_fields):
        return False
    for scope in (capability.actions, capability.resources):
        if not isinstance(scope, frozenset) or not scope:
            return False
        if any(not isinstance(value, str) or not value.strip() for value in scope):
            return False
    if capability.parent_id is not None and (
        not isinstance(capability.parent_id, str) or not capability.parent_id.strip()
    ):
        return False
    if not isinstance(capability.ancestor_ids, tuple):
        return False
    if any(not isinstance(value, str) or not value.strip() for value in capability.ancestor_ids):
        return False
    if len(set(capability.ancestor_ids)) != len(capability.ancestor_ids):
        return False
    if capability.capability_id in capability.ancestor_ids:
        return False
    if capability.parent_id is None:
        if capability.ancestor_ids:
            return False
    elif not capability.ancestor_ids or capability.ancestor_ids[-1] != capability.parent_id:
        return False
    for value, name in (
        (capability.audience, "audience"),
        (capability.workflow_id, "workflow_id"),
    ):
        if value is not None and (not isinstance(value, str) or not value.strip()):
            return False
    expiry = capability.expires_at
    if expiry is not None and (
        isinstance(expiry, bool) or not isinstance(expiry, int) or expiry <= 0
    ):
        return False
    return True


def verify_capability_issuer(
    signed: SignedCapability,
    registry: IdentityRegistry,
) -> bool:
    """Verify that the registered key for capability.issuer signed it."""
    if not isinstance(signed, SignedCapability) or not isinstance(registry, IdentityRegistry):
        return False
    if not _is_well_formed_capability(signed.capability):
        return False
    trusted_key = registry.get_public_key(signed.capability.issuer)
    if trusted_key is None:
        return False
    return verify_signed_capability(signed, trusted_key)


def verify_delegation_chain(
    chain: Sequence[SignedCapability],
    registry: IdentityRegistry,
) -> bool:
    """Verify signatures, issuer relationships, lineage, scope, and context."""
    if not isinstance(registry, IdentityRegistry):
        return False
    if not isinstance(chain, (list, tuple)) or not chain:
        return False

    capabilities: list[Capability] = []
    for signed in chain:
        if not verify_capability_issuer(signed, registry):
            return False
        capabilities.append(signed.capability)

    capability_ids = [capability.capability_id for capability in capabilities]
    if len(set(capability_ids)) != len(capability_ids):
        return False

    root = capabilities[0]
    if root.parent_id is not None or root.ancestor_ids != ():
        return False
    if root.issuer != root.root_principal:
        return False

    for index in range(1, len(capabilities)):
        parent = capabilities[index - 1]
        child = capabilities[index]
        expected_ancestors = tuple(cap.capability_id for cap in capabilities[:index])
        if child.parent_id != parent.capability_id:
            return False
        if child.ancestor_ids != expected_ancestors:
            return False
        if child.issuer != parent.subject:
            return False
        if child.root_principal != root.root_principal:
            return False
        if child.audience != parent.audience:
            return False
        if child.workflow_id != parent.workflow_id:
            return False
        if child.expires_at != parent.expires_at:
            return False
        if not child.actions.issubset(parent.actions):
            return False
        if not child.resources.issubset(parent.resources):
            return False
    return True
