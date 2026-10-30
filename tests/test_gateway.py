from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import AuthorizationError, delegate, issue_root_capability
from chainguard.gateway import ActionRequest, EnforcementGateway, ReplayGuard, sign_action_request
from chainguard.identity import IdentityRegistry
from chainguard.integrity import sign_capability
from chainguard.revocation import RevocationRegistry


class RecordingAdapter:
    def __init__(self):
        self.calls = []

    def execute(self, request):
        self.calls.append(request)
        return {"executed": request.action, "resource": request.resource}


@pytest.fixture
def environment():
    human_key = Ed25519PrivateKey.generate()
    agent_a_key = Ed25519PrivateKey.generate()
    agent_b_key = Ed25519PrivateKey.generate()

    identities = IdentityRegistry()
    identities.register("human", human_key.public_key().public_bytes_raw())
    identities.register("agent-a", agent_a_key.public_key().public_bytes_raw())
    identities.register("agent-b", agent_b_key.public_key().public_bytes_raw())

    root = issue_root_capability(
        "human", "agent-a", {"read", "summarize"}, {"report-1"},
        audience="report-service",
        workflow_id="quarterly-review",
        expires_at=2_000_000_000,
    )
    child = delegate(root, "agent-a", "agent-b", {"read"}, {"report-1"})
    chain = (
        sign_capability(root, human_key),
        sign_capability(child, agent_a_key),
    )
    revocations = RevocationRegistry()
    gateway = EnforcementGateway(
        identities, revocations, clock=lambda: 1_900_000_000
    )
    return gateway, identities, revocations, root, child, chain, agent_b_key


def valid_request(request_id="request-001", **changes):
    request = ActionRequest(
        request_id=request_id,
        actor="agent-b",
        action="read",
        resource="report-1",
        audience="report-service",
        workflow_id="quarterly-review",
    )
    return replace(request, **changes)


def signed_request(agent_key, request_id="request-001", **changes):
    return sign_action_request(valid_request(request_id, **changes), agent_key)


def test_gateway_executes_valid_authorized_request(environment):
    gateway, _, _, _, _, chain, agent_b_key = environment
    adapter = RecordingAdapter()

    result = gateway.execute(chain, signed_request(agent_b_key), adapter)

    assert result == {"executed": "read", "resource": "report-1"}
    assert len(adapter.calls) == 1


def test_gateway_rejects_action_escalation_before_execution(environment):
    gateway, _, _, _, _, chain, agent_b_key = environment
    adapter = RecordingAdapter()

    with pytest.raises(AuthorizationError, match="outside"):
        gateway.execute(chain, signed_request(agent_b_key, action="delete"), adapter)

    assert adapter.calls == []


def test_gateway_rejects_resource_escalation_before_execution(environment):
    gateway, _, _, _, _, chain, agent_b_key = environment
    adapter = RecordingAdapter()

    with pytest.raises(AuthorizationError, match="outside"):
        gateway.execute(chain, signed_request(agent_b_key, resource="payroll"), adapter)

    assert adapter.calls == []


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("actor", "agent-a", "signature or actor identity"),
        ("audience", "payment-service", "audience"),
        ("workflow_id", "different-workflow", "workflow"),
    ],
)
def test_gateway_rejects_context_mismatch(environment, field, value, message):
    gateway, _, _, _, _, chain, agent_b_key = environment
    adapter = RecordingAdapter()

    with pytest.raises(AuthorizationError, match=message):
        gateway.execute(chain, signed_request(agent_b_key, **{field: value}), adapter)

    assert adapter.calls == []


def test_gateway_rejects_expired_capability(environment):
    _, identities, revocations, _, _, chain, agent_b_key = environment
    expired_gateway = EnforcementGateway(
        identities, revocations, clock=lambda: 2_000_000_000
    )
    adapter = RecordingAdapter()

    with pytest.raises(AuthorizationError, match="expired"):
        expired_gateway.execute(chain, signed_request(agent_b_key), adapter)

    assert adapter.calls == []


def test_gateway_rejects_revoked_ancestor(environment):
    gateway, _, revocations, root, _, chain, agent_b_key = environment
    revocations.revoke(root)
    adapter = RecordingAdapter()

    with pytest.raises(AuthorizationError, match="revoked"):
        gateway.execute(chain, signed_request(agent_b_key), adapter)

    assert adapter.calls == []


def test_gateway_rejects_replayed_request_id(environment):
    gateway, _, _, _, _, chain, agent_b_key = environment
    adapter = RecordingAdapter()

    signed = signed_request(agent_b_key)
    gateway.execute(chain, signed, adapter)
    with pytest.raises(AuthorizationError, match="replay"):
        gateway.execute(chain, signed, adapter)

    assert len(adapter.calls) == 1


def test_gateway_rejects_malformed_chain_before_execution(environment):
    gateway, _, _, _, _, chain, agent_b_key = environment
    adapter = RecordingAdapter()

    with pytest.raises(AuthorizationError, match="chain verification"):
        gateway.execute(
            (replace(chain[0], capability=object()),), signed_request(agent_b_key), adapter
        )

    assert adapter.calls == []


def test_gateway_rejects_capability_without_execution_context():
    human_key = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    identities = IdentityRegistry()
    identities.register("human", human_key.public_key().public_bytes_raw())
    identities.register("agent", agent_key.public_key().public_bytes_raw())
    root = issue_root_capability("human", "agent", {"read"}, {"report"})
    chain = (sign_capability(root, human_key),)
    gateway = EnforcementGateway(
        identities, RevocationRegistry(), clock=lambda: 100
    )
    adapter = RecordingAdapter()
    request = ActionRequest(
        "req-no-context", "agent", "read", "report", "report-service", "workflow"
    )

    with pytest.raises(AuthorizationError, match="audience"):
        gateway.execute(chain, sign_action_request(request, agent_key), adapter)

    assert adapter.calls == []


def test_request_id_stays_consumed_if_adapter_raises(environment):
    gateway, _, _, _, _, chain, agent_b_key = environment
    signed = signed_request(agent_b_key, "uncertain-outcome")

    class FailingAdapter:
        def execute(self, request):
            raise RuntimeError("service failure")

    with pytest.raises(RuntimeError, match="service failure"):
        gateway.execute(
            chain, signed, FailingAdapter()
        )

    with pytest.raises(AuthorizationError, match="replay"):
        gateway.execute(
            chain, signed, RecordingAdapter()
        )


def test_concurrent_replay_allows_only_one_adapter_execution(environment):
    from concurrent.futures import ThreadPoolExecutor

    gateway, _, _, _, _, chain, agent_b_key = environment
    adapter = RecordingAdapter()
    signed = signed_request(agent_b_key, "concurrent-request")

    def attempt():
        try:
            gateway.execute(chain, signed, adapter)
            return "allowed"
        except AuthorizationError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(8)))

    assert outcomes.count("allowed") == 1
    assert outcomes.count("rejected") == 7
    assert len(adapter.calls) == 1



def test_revocation_after_gateway_check_can_precede_adapter_execution(environment):
    """Document the current TOCTOU gap; this is an expected limitation test."""
    _, identities, revocations, root, _, chain, agent_b_key = environment

    class RevokeImmediatelyAfterActiveCheck(ReplayGuard):
        def consume(self, request_id):
            super().consume(request_id)
            # Gateway calls consume only after require_active() has returned.
            revocations.revoke(root)

    gateway = EnforcementGateway(
        identities,
        revocations,
        replay_guard=RevokeImmediatelyAfterActiveCheck(),
        clock=lambda: 1_900_000_000,
    )
    adapter = RecordingAdapter()

    result = gateway.execute(chain, signed_request(agent_b_key, "late-revoke"), adapter)

    assert result == {"executed": "read", "resource": "report-1"}
    assert revocations.is_revoked(root)
    assert len(adapter.calls) == 1
