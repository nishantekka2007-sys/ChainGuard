"""Deterministic TOCTOU experiment for capability revocation.

This experiment injects revocation at the gateway's replay-consumption
boundary. It demonstrates ordering in the current implementation; it is not
a probabilistic thread-race benchmark or a production concurrency proof.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import AuthorizationError, issue_root_capability
from chainguard.gateway import (
    ActionRequest,
    EnforcementGateway,
    ReplayGuard,
    sign_action_request,
)
from chainguard.identity import IdentityRegistry
from chainguard.integrity import sign_capability
from chainguard.revocation import RevocationRegistry


class RecordingAdapter:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: ActionRequest) -> dict[str, str]:
        self.calls += 1
        return {"status": "executed", "action": request.action}


class RevokeDuringReplayConsume(ReplayGuard):
    """Inject revocation after gateway's active check, before adapter call."""

    def __init__(self, revocations: RevocationRegistry, capability) -> None:
        super().__init__()
        self.revocations = revocations
        self.capability = capability

    def consume(self, request_id: str) -> None:
        super().consume(request_id)
        self.revocations.revoke(self.capability)


@dataclass(frozen=True)
class CaseResult:
    scenario: str
    revoked_before_adapter: bool
    gateway_rejected: bool
    adapter_calls: int
    observed_status: str


def _environment(replay_guard: ReplayGuard | None = None):
    human_key = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    identities = IdentityRegistry()
    identities.register("human", human_key.public_key().public_bytes_raw())
    identities.register("agent", agent_key.public_key().public_bytes_raw())

    capability = issue_root_capability(
        "human", "agent", {"read"}, {"report-1"},
        audience="report-service", workflow_id="toctou-study",
        expires_at=4_000_000_000,
    )
    chain = (sign_capability(capability, human_key),)
    revocations = RevocationRegistry()
    gateway = EnforcementGateway(
        identities, revocations, replay_guard=replay_guard,
        clock=lambda: 1_900_000_000,
    )
    request = ActionRequest(
        "toctou-request", "agent", "read", "report-1",
        "report-service", "toctou-study",
    )
    signed_request = sign_action_request(request, agent_key)
    return capability, chain, revocations, gateway, signed_request


def run_experiment() -> dict[str, object]:
    """Compare revocation before check with revocation after the check."""

    # Control: revocation is visible when the gateway performs its check.
    capability, chain, revocations, gateway, signed = _environment()
    adapter = RecordingAdapter()
    revocations.revoke(capability)
    rejected = False
    try:
        gateway.execute(chain, signed, adapter)
    except AuthorizationError:
        rejected = True
    before = CaseResult(
        scenario="revoked_before_gateway_check",
        revoked_before_adapter=revocations.is_revoked(capability),
        gateway_rejected=rejected,
        adapter_calls=adapter.calls,
        observed_status="rejected" if rejected else "unexpectedly_executed",
    )

    # Controlled interleaving: revoke only after require_active() has returned.
    capability, chain, revocations, _, signed = _environment()
    late_guard = RevokeDuringReplayConsume(revocations, capability)
    identities = IdentityRegistry()
    # Reconstruct the trusted identity registry from the signed chain's issuer
    # key is not possible from a signature alone; build a fresh environment
    # with the injected guard so the gateway retains the proper registry.
    capability, chain, revocations, gateway, signed = _environment(late_guard)
    adapter = RecordingAdapter()
    rejected = False
    try:
        gateway.execute(chain, signed, adapter)
    except AuthorizationError:
        rejected = True
    after = CaseResult(
        scenario="revoked_after_gateway_check_before_adapter",
        revoked_before_adapter=revocations.is_revoked(capability),
        gateway_rejected=rejected,
        adapter_calls=adapter.calls,
        observed_status="rejected" if rejected else "executed_after_revocation",
    )

    return {
        "experiment": "chainguard_revocation_toctou_v1",
        "method": "deterministic_interleaving_at_replay_guard_boundary",
        "warning": (
            "This demonstrates a check/use ordering gap in the current local "
            "gateway. It is not a probabilistic race benchmark, proof of an "
            "exploitable remote deployment, or evidence about untested systems."
        ),
        "cases": [before.__dict__, after.__dict__],
        "interpretation": (
            "The gateway rejects revocation visible at its check. Revocation "
            "that occurs after that check is not rechecked before adapter "
            "invocation, so the adapter can execute after revocation."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="-", help="JSON output path, or '-' for stdout")
    args = parser.parse_args()
    rendered = json.dumps(run_experiment(), indent=2, sort_keys=True)
    if args.output == "-":
        print(rendered)
    else:
        with open(args.output, "w", encoding="utf-8") as output:
            output.write(rendered + "\\n")


if __name__ == "__main__":
    main()
