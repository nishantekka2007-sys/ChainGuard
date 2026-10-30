"""Fail-closed enforcement boundary for protected tool operations.

This first gateway is synchronous and process-local. Replay state and
revocation checks are not distributed or transactionally coupled to external
tool execution; see the project limitations.
"""

from dataclasses import dataclass
from threading import Lock
import time
from typing import Callable, Protocol

from chainguard.core import AuthorizationError
from chainguard.identity import IdentityRegistry
from chainguard.integrity import SignedCapability
from chainguard.revocation import RevocationRegistry
from chainguard.verification import verify_delegation_chain


@dataclass(frozen=True)
class ActionRequest:
    """A minimal, context-bound request for one protected operation."""

    request_id: str
    actor: str
    action: str
    resource: str
    audience: str
    workflow_id: str


class ToolAdapter(Protocol):
    """Adapter contract for the protected service behind the gateway."""

    def execute(self, request: ActionRequest) -> object:
        """Execute exactly the operation described by an authorized request."""
        ...


class ReplayGuard:
    """Thread-safe, in-memory single-use request identifier registry."""

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._lock = Lock()

    def consume(self, request_id: str) -> None:
        """Atomically consume an ID or reject it if it has already been used."""
        with self._lock:
            if request_id in self._seen:
                raise AuthorizationError("Request replay detected.")
            self._seen.add(request_id)


class EnforcementGateway:
    """Verify authority and context before allowing a protected tool call.

    The protected service must not be invocable with independent agent-held
    credentials. This gateway alone cannot prevent infrastructure-level bypass.
    """

    def __init__(
        self,
        identity_registry: IdentityRegistry,
        revocation_registry: RevocationRegistry,
        *,
        replay_guard: ReplayGuard | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(identity_registry, IdentityRegistry):
            raise AuthorizationError("A trusted identity registry is required.")
        if not isinstance(revocation_registry, RevocationRegistry):
            raise AuthorizationError("A revocation registry is required.")
        if not callable(clock):
            raise AuthorizationError("A valid clock function is required.")
        self._identities = identity_registry
        self._revocations = revocation_registry
        self._replay = replay_guard if replay_guard is not None else ReplayGuard()
        self._clock = clock

    @staticmethod
    def _validate_request(request: ActionRequest) -> None:
        if not isinstance(request, ActionRequest):
            raise AuthorizationError("A valid action request is required.")
        fields = (
            request.request_id, request.actor, request.action,
            request.resource, request.audience, request.workflow_id,
        )
        if any(not isinstance(value, str) or not value.strip() for value in fields):
            raise AuthorizationError("Every request field must be a non-empty string.")

    def execute(
        self,
        chain: list[SignedCapability] | tuple[SignedCapability, ...],
        request: ActionRequest,
        adapter: ToolAdapter,
    ) -> object:
        """Execute only after all authorization checks have passed.

        The request ID is consumed before adapter invocation. If the adapter
        fails after receiving the request, the ID stays consumed to avoid
        accidental duplicate execution. Retryable services need their own
        idempotency protocol for uncertain outcomes.
        """
        self._validate_request(request)
        if not callable(getattr(adapter, "execute", None)):
            raise AuthorizationError("A valid protected tool adapter is required.")
        if not verify_delegation_chain(chain, self._identities):
            raise AuthorizationError("Delegation chain verification failed.")

        capability = chain[-1].capability
        if capability.subject != request.actor:
            raise AuthorizationError("Request actor is not the capability subject.")
        if request.action not in capability.actions:
            raise AuthorizationError("Action is outside the granted capability scope.")
        if request.resource not in capability.resources:
            raise AuthorizationError("Resource is outside the granted capability scope.")
        if capability.audience is None or capability.audience != request.audience:
            raise AuthorizationError("Request audience does not match the capability.")
        if capability.workflow_id is None or capability.workflow_id != request.workflow_id:
            raise AuthorizationError("Request workflow does not match the capability.")
        if capability.expires_at is None:
            raise AuthorizationError("Capability expiry is required for execution.")
        if self._clock() >= capability.expires_at:
            raise AuthorizationError("Capability has expired.")

        try:
            self._revocations.require_active(capability)
        except AuthorizationError as exc:
            raise AuthorizationError("Capability is revoked or inactive.") from exc

        self._replay.consume(request.request_id)
        return adapter.execute(request)
