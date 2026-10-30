"""Small, reproducible baseline benchmark for ChainGuard.

This is a synthetic microbenchmark, not a production workload or proof of
security. It compares deliberately simplified policy baselines on one benign
request and one downstream privilege-escalation attack.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import AuthorizationError, Capability, delegate, issue_root_capability
from chainguard.gateway import (
    ActionRequest,
    EnforcementGateway,
    ReplayGuard,
    SignedActionRequest,
    sign_action_request,
)
from chainguard.identity import IdentityRegistry
from chainguard.integrity import SignedCapability, sign_capability, verify_signed_capability
from chainguard.revocation import RevocationRegistry
from chainguard.verification import verify_delegation_chain


@dataclass(frozen=True)
class Trial:
    name: str
    chain: tuple[SignedCapability, ...]
    signed_request: SignedActionRequest
    expected_authorized: bool


@dataclass
class Result:
    baseline: str
    scenario: str
    trials: int
    accepted: int
    rejected: int
    attack_success_rate: float | None
    false_rejection_rate: float | None
    benign_completion_rate: float | None
    median_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = (len(ordered) - 1) * percentile
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = index - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def build_trials() -> tuple[IdentityRegistry, Ed25519PrivateKey, tuple[Trial, Trial]]:
    human_key = Ed25519PrivateKey.generate()
    agent_a_key = Ed25519PrivateKey.generate()
    agent_b_key = Ed25519PrivateKey.generate()
    identities = IdentityRegistry()
    for name, key in (
        ("human", human_key),
        ("agent-a", agent_a_key),
        ("agent-b", agent_b_key),
    ):
        identities.register(name, key.public_key().public_bytes_raw())

    root = issue_root_capability(
        "human", "agent-a", {"read"}, {"report-1"},
        audience="report-service", workflow_id="benchmark-1",
        expires_at=4_000_000_000,
    )
    valid_child = delegate(root, "agent-a", "agent-b", {"read"}, {"report-1"})
    escalated_child = Capability(
        capability_id="attack-child",
        root_principal=root.root_principal,
        issuer="agent-a",
        subject="agent-b",
        actions=frozenset({"read", "delete"}),
        resources=frozenset({"report-1"}),
        parent_id=root.capability_id,
        ancestor_ids=(root.capability_id,),
        audience=root.audience,
        workflow_id=root.workflow_id,
        expires_at=root.expires_at,
    )

    root_signed = sign_capability(root, human_key)
    valid_chain = (root_signed, sign_capability(valid_child, agent_a_key))
    attack_chain = (root_signed, sign_capability(escalated_child, agent_a_key))

    benign_request = ActionRequest(
        "benign-1", "agent-b", "read", "report-1",
        "report-service", "benchmark-1",
    )
    attack_request = ActionRequest(
        "attack-1", "agent-b", "delete", "report-1",
        "report-service", "benchmark-1",
    )
    benign = Trial(
        "benign_read", valid_chain,
        sign_action_request(benign_request, agent_b_key), True,
    )
    attack = Trial(
        "downstream_scope_escalation", attack_chain,
        sign_action_request(attack_request, agent_b_key), False,
    )
    return identities, agent_b_key, (benign, attack)


def _authorize(
    baseline: str,
    trial: Trial,
    identities: IdentityRegistry,
    iteration: int,
    signed_request: SignedActionRequest,
    gateway: EnforcementGateway | None,
    adapter: _NoOpAdapter,
) -> bool:
    leaf = trial.chain[-1]
    capability = leaf.capability
    request = signed_request.request

    if baseline == "B0_no_enforcement":
        return True
    if baseline == "B1_scope_only":
        return request.action in capability.actions and request.resource in capability.resources
    if baseline == "B2_signature_only":
        return verify_signed_capability(
            leaf, identities.get_public_key(capability.issuer) or b""
        )
    if baseline == "B4_full_chain":
        return (
            verify_delegation_chain(trial.chain, identities)
            and request.action in capability.actions
            and request.resource in capability.resources
        )
    if baseline == "B5_full_gateway":
        if gateway is None:
            raise ValueError("The full-gateway baseline requires a prepared gateway")
        try:
            gateway.execute(trial.chain, signed_request, adapter)
            return True
        except AuthorizationError:
            return False
    raise ValueError(f"Unknown baseline: {baseline}")


class _NoOpAdapter:
    def execute(self, request: ActionRequest) -> bool:
        return True


_actor_private_key_for_benchmark: Ed25519PrivateKey


def run_benchmark(trials: int = 100) -> dict[str, object]:
    """Run benign and adversarial trials against the baseline matrix."""
    if isinstance(trials, bool) or not isinstance(trials, int) or trials < 1:
        raise ValueError("trials must be a positive integer")

    identities, actor_key, scenarios = build_trials()

    baselines = (
        "B0_no_enforcement",
        "B1_scope_only",
        "B2_signature_only",
        "B4_full_chain",
        "B5_full_gateway",
    )
    results: list[Result] = []
    for baseline in baselines:
        for scenario in scenarios:
            durations: list[float] = []
            accepted = 0
            # Exclude gateway construction and request signing from the measured
            # authorization decision path. Reuse one gateway and adapter, while
            # assigning a fresh request ID to each single-use execution.
            gateway = (
                EnforcementGateway(
                    identities, RevocationRegistry(), replay_guard=ReplayGuard(),
                    clock=lambda: 1_900_000_000,
                )
                if baseline == "B5_full_gateway" else None
            )
            adapter = _NoOpAdapter()
            for iteration in range(trials):
                request = scenario.signed_request.request
                signed = scenario.signed_request
                if baseline == "B5_full_gateway":
                    unique_request = ActionRequest(
                        f"{request.request_id}-{iteration}", request.actor,
                        request.action, request.resource, request.audience,
                        request.workflow_id,
                    )
                    signed = sign_action_request(unique_request, actor_key)
                start = time.perf_counter_ns()
                allowed = _authorize(
                    baseline, scenario, identities, iteration, signed, gateway, adapter
                )
                durations.append((time.perf_counter_ns() - start) / 1_000_000)
                accepted += int(allowed)

            rejected = trials - accepted
            attack_rate = (
                accepted / trials if not scenario.expected_authorized else None
            )
            false_rejection = (
                rejected / trials if scenario.expected_authorized else None
            )
            benign_completion = (
                accepted / trials if scenario.expected_authorized else None
            )
            results.append(Result(
                baseline=baseline,
                scenario=scenario.name,
                trials=trials,
                accepted=accepted,
                rejected=rejected,
                attack_success_rate=attack_rate,
                false_rejection_rate=false_rejection,
                benign_completion_rate=benign_completion,
                median_latency_ms=statistics.median(durations),
                p95_latency_ms=_percentile(durations, 0.95),
                p99_latency_ms=_percentile(durations, 0.99),
            ))

    return {
        "benchmark": "chainguard_synthetic_baseline_v2",
        "measurement_boundary": (
            "Gateway construction and action-request signing are excluded from "
            "decision latency; one gateway and adapter are reused per scenario."
        ),
        "warning": (
            "Synthetic microbenchmark only. It covers one benign request and "
            "one signed downstream scope-escalation attack; results are not "
            "generalizable security guarantees or production performance claims."
        ),
        "trials_per_scenario": trials,
        "baselines": list(baselines),
        "results": [result.__dict__ for result in results],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--output", default="-", help="JSON output path, or '-' for stdout")
    args = parser.parse_args()
    report = run_benchmark(args.trials)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output == "-":
        print(rendered)
    else:
        with open(args.output, "w", encoding="utf-8") as output:
            output.write(rendered + "\n")


if __name__ == "__main__":
    main()
