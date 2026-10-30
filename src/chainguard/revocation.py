"""In-memory capability revocation for the ChainGuard prototype.

Revoking an ancestor invalidates every descendant that records that ancestor
in its delegation lineage. This registry is process-local and is not a
distributed or cryptographically protected revocation service.
"""

from dataclasses import dataclass, field

from chainguard.core import AuthorizationError, Capability


@dataclass
class RevocationRegistry:
    """Track revoked capability identifiers in the current process."""

    _revoked_ids: set[str] = field(default_factory=set, repr=False)

    def revoke(self, capability: Capability) -> None:
        """Revoke one capability; descendants become inactive as well."""
        if not isinstance(capability, Capability):
            raise AuthorizationError("A valid capability is required.")
        self._revoked_ids.add(capability.capability_id)

    def is_revoked(self, capability: Capability) -> bool:
        """Return whether this capability or any ancestor was revoked."""
        if not isinstance(capability, Capability):
            raise AuthorizationError("A valid capability is required.")

        lineage = capability.ancestor_ids + (capability.capability_id,)
        return any(capability_id in self._revoked_ids for capability_id in lineage)

    def require_active(self, capability: Capability) -> None:
        """Reject use of a revoked capability or one with a revoked ancestor."""
        if self.is_revoked(capability):
            raise AuthorizationError("Capability has been revoked.")
