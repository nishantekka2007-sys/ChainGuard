"""Initial scope-attenuation model for ChainGuard.

This module models delegation policy. It is not yet a cryptographic security
boundary: capabilities are ordinary Python objects until later milestones add
authentication, integrity protection, and runtime enforcement.
"""

from dataclasses import dataclass
from uuid import uuid4


class AuthorizationError(Exception):
    """Raised when a requested delegation exceeds granted authority."""


@dataclass(frozen=True)
class Capability:
    """An immutable-in-process record of a delegated permission scope."""

    capability_id: str
    root_principal: str
    issuer: str
    subject: str
    actions: frozenset[str]
    resources: frozenset[str]
    parent_id: str | None = None


def _validated_scope(values: set[str], field_name: str) -> frozenset[str]:
    """Return a non-empty, normalized immutable scope."""
    if not isinstance(values, set) or not values:
        raise AuthorizationError(f"{field_name} must be a non-empty set.")

    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise AuthorizationError(
            f"Every {field_name} entry must be a non-empty string."
        )

    return frozenset(value.strip() for value in values)


def _validated_identity(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationError(f"{field_name} must be a non-empty string.")
    return value.strip()


def issue_root_capability(
    human: str,
    first_agent: str,
    actions: set[str],
    resources: set[str],
) -> Capability:
    """Create the first capability from a human-authorized scope."""
    return Capability(
        capability_id=str(uuid4()),
        root_principal=_validated_identity(human, "human"),
        issuer=_validated_identity(human, "human"),
        subject=_validated_identity(first_agent, "first_agent"),
        actions=_validated_scope(actions, "actions"),
        resources=_validated_scope(resources, "resources"),
    )


def delegate(
    parent: Capability,
    delegator: str,
    new_subject: str,
    actions: set[str],
    resources: set[str],
) -> Capability:
    """Delegate only a subset of the parent's actions and resources."""
    if not isinstance(parent, Capability):
        raise AuthorizationError("A valid parent capability is required.")

    delegator = _validated_identity(delegator, "delegator")
    new_subject = _validated_identity(new_subject, "new_subject")
    requested_actions = _validated_scope(actions, "actions")
    requested_resources = _validated_scope(resources, "resources")

    if delegator != parent.subject:
        raise AuthorizationError(
            "Only the capability's authorized subject can delegate it."
        )

    if not requested_actions.issubset(parent.actions):
        raise AuthorizationError("Privilege escalation: unauthorized action.")

    if not requested_resources.issubset(parent.resources):
        raise AuthorizationError("Privilege escalation: unauthorized resource.")

    return Capability(
        capability_id=str(uuid4()),
        root_principal=parent.root_principal,
        issuer=delegator,
        subject=new_subject,
        actions=requested_actions,
        resources=requested_resources,
        parent_id=parent.capability_id,
    )
