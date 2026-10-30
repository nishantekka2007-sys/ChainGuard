"""Fail-closed enforcement boundary for protected tool operations.

The gateway is synchronous. Its default replay and revocation path is process-local; optional SQLite-backed stores support single-host persistence. SQLiteAdmissionCoordinator can serialize admission against revocation writes on one host, but does not make external tool execution atomic or provide dispatch-time fencing.
"""

from dataclasses import dataclass
import json
from threading import Lock
import time
from typing import Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

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


@dataclass(frozen=True)
class SignedActionRequest:
    """An action request signed by the private key of its claimed actor."""

    request: ActionRequest
    signer_public_key: bytes
    signature: bytes


def _validate_action_request(request: ActionRequest) -> None:
    if not isinstance(request, ActionRequest):
        raise AuthorizationError("A valid action request is required.")
    fields = (
        request.request_id, request.actor, request.action,
        request.resource, request.audience, request.workflow_id,
    )
    if any(not isinstance(value, str) or not value.strip() for value in fields):
        raise AuthorizationError("Every request field must be a non-empty string.")


def _canonical_request(request: ActionRequest) -> bytes:
    """Serialize every request field deterministically before signing."""
    _validate_action_request(request)
    payload = {
        "request_id": request.request_id,
        "actor": request.actor,
        "action": request.action,
        "resource": request.resource,
        "audience": request.audience,
        "workflow_id": request.workflow_id,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign_action_request(
    request: ActionRequest,
    private_key: Ed25519PrivateKey,
) -> SignedActionRequest:
    """Sign a request to prove possession of the actor's registered key."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise AuthorizationError("A valid Ed25519 private key is required.")
    payload = _canonical_request(request)
    public_key = private_key.public_key().public_bytes_raw()
    return SignedActionRequest(
        request=request,
        signer_public_key=public_key,
        signature=private_key.sign(payload),
    )


def verify_action_request(
    signed: SignedActionRequest,
    registry: IdentityRegistry,
) -> bool:
    """Verify request integrity and proof of possession for its claimed actor."""
    if not isinstance(signed, SignedActionRequest):
        return False
    if not isinstance(registry, IdentityRegistry):
        return False
    if not isinstance(signed.signer_public_key, bytes):
        return False
    if not isinstance(signed.signature, bytes):
        return False
    try:
        payload = _canonical_request(signed.request)
        trusted_key = registry.get_public_key(signed.request.actor)
        if trusted_key is None or trusted_key != signed.signer_public_key:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(trusted_key)
        public_key.verify(signed.signature, payload)
    except (AuthorizationError, InvalidSignature, ValueError, TypeError, AttributeError):
        return False
    return True


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
    """Verify authority and request ownership before allowing a protected call.

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
        admission_coordinator: object | None = None,
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
        if admission_coordinator is not None and not callable(getattr(admission_coordinator, "admit", None)):
            raise AuthorizationError("A valid admission coordinator is required.")
        self._admission_coordinator = admission_coordinator

    def execute(
        self,
        chain: list[SignedCapability] | tuple[SignedCapability, ...],
        signed_request: SignedActionRequest,
        adapter: ToolAdapter,
    ) -> object:
        """Execute only after all authorization and proof-of-possession checks.

        The request ID is consumed before adapter invocation. If the adapter
        fails after receiving the request, the ID stays consumed to avoid
        accidental duplicate execution. Retryable services need their own
        idempotency protocol for uncertain outcomes.
        """
        if not isinstance(signed_request, SignedActionRequest):
            raise AuthorizationError("A signed action request is required.")
        request = signed_request.request
        _validate_action_request(request)
        if not callable(getattr(adapter, "execute", None)):
            raise AuthorizationError("A valid protected tool adapter is required.")
        if not verify_action_request(signed_request, self._identities):
            raise AuthorizationError("Action request signature or actor identity is invalid.")
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

        if self._admission_coordinator is not None:
            # Admission and revocation are serialized by the shared coordinator.
            # A request admitted first may still complete after a later revoke.
            self._admission_coordinator.admit(capability, request.request_id)
        else:
            try:
                self._revocations.require_active(capability)
            except AuthorizationError as exc:
                raise AuthorizationError("Capability is revoked or inactive.") from exc
            self._replay.consume(request.request_id)

        return adapter.execute(request)
