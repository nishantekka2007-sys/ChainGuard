"""Capability model and scope-attenuating delegation for ChainGuard."""

from dataclasses import dataclass
from uuid import uuid4


class AuthorizationError(Exception):
    """Raised when a requested operation or delegation is not authorized."""


@dataclass(frozen=True)
class Capability:
    """An immutable capability bound to an issuer, subject, and execution context."""

    capability_id: str
    root_principal: str
    issuer: str
    subject: str
    actions: frozenset[str]
    resources: frozenset[str]
    parent_id: str | None = None
    ancestor_ids: tuple[str, ...] = ()
    audience: str | None = None
    workflow_id: str | None = None
    expires_at: int | None = None


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


def _optional_context(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _validated_identity(value, field_name)


def _validated_expiry(value: int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AuthorizationError("expires_at must be a positive Unix timestamp.")
    return value


def issue_root_capability(
    human: str,
    first_agent: str,
    actions: set[str],
    resources: set[str],
    *,
    audience: str | None = None,
    workflow_id: str | None = None,
    expires_at: int | None = None,
) -> Capability:
    """Create the first capability from a human-authorized scope."""
    return Capability(
        capability_id=str(uuid4()),
        root_principal=_validated_identity(human, "human"),
        issuer=_validated_identity(human, "human"),
        subject=_validated_identity(first_agent, "first_agent"),
        actions=_validated_scope(actions, "actions"),
        resources=_validated_scope(resources, "resources"),
        audience=_optional_context(audience, "audience"),
        workflow_id=_optional_context(workflow_id, "workflow_id"),
        expires_at=_validated_expiry(expires_at),
    )


def delegate(
    parent: Capability,
    delegator: str,
    new_subject: str,
    actions: set[str],
    resources: set[str],
) -> Capability:
    """Delegate a subset without changing the parent's execution context."""
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
        ancestor_ids=parent.ancestor_ids + (parent.capability_id,),
        audience=parent.audience,
        workflow_id=parent.workflow_id,
        expires_at=parent.expires_at,
    )
