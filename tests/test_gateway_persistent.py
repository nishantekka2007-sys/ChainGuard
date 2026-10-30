from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from chainguard.core import AuthorizationError, issue_root_capability
from chainguard.gateway import ActionRequest, EnforcementGateway, sign_action_request
from chainguard.integrity import sign_capability
from chainguard.storage import (
    SQLiteIdentityRegistry,
    SQLiteReplayGuard,
    SQLiteRevocationRegistry,
)


class CountingAdapter:
    def __init__(self):
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return "executed"


def test_gateway_replay_state_survives_gateway_restart(tmp_path):
    database = tmp_path / "chainguard.sqlite3"
    human_key = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    identities = SQLiteIdentityRegistry(database)
    identities.register("human", human_key.public_key().public_bytes_raw())
    identities.register("agent", agent_key.public_key().public_bytes_raw())

    capability = issue_root_capability(
        "human", "agent", {"read"}, {"report"},
        audience="report-service",
        workflow_id="review-1",
        expires_at=2_000_000_000,
    )
    chain = (sign_capability(capability, human_key),)
    request = ActionRequest(
        "durable-request-1", "agent", "read", "report",
        "report-service", "review-1",
    )
    signed_request = sign_action_request(request, agent_key)

    first_gateway = EnforcementGateway(
        identities,
        SQLiteRevocationRegistry(database),
        replay_guard=SQLiteReplayGuard(database),
        clock=lambda: 1_900_000_000,
    )
    first_adapter = CountingAdapter()
    assert first_gateway.execute(chain, signed_request, first_adapter) == "executed"
    assert first_adapter.calls == 1

    second_gateway = EnforcementGateway(
        SQLiteIdentityRegistry(database),
        SQLiteRevocationRegistry(database),
        replay_guard=SQLiteReplayGuard(database),
        clock=lambda: 1_900_000_000,
    )
    second_adapter = CountingAdapter()
    with pytest.raises(AuthorizationError, match="replay"):
        second_gateway.execute(chain, signed_request, second_adapter)
    assert second_adapter.calls == 0


def test_gateway_observes_revocation_after_reopening_database(tmp_path):
    database = tmp_path / "chainguard.sqlite3"
    human_key = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    identities = SQLiteIdentityRegistry(database)
    identities.register("human", human_key.public_key().public_bytes_raw())
    identities.register("agent", agent_key.public_key().public_bytes_raw())
    capability = issue_root_capability(
        "human", "agent", {"read"}, {"report"},
        audience="report-service",
        workflow_id="review-1",
        expires_at=2_000_000_000,
    )
    chain = (sign_capability(capability, human_key),)
    signed_request = sign_action_request(
        ActionRequest(
            "durable-request-2", "agent", "read", "report",
            "report-service", "review-1",
        ),
        agent_key,
    )
    SQLiteRevocationRegistry(database).revoke(capability)

    gateway = EnforcementGateway(
        SQLiteIdentityRegistry(database),
        SQLiteRevocationRegistry(database),
        replay_guard=SQLiteReplayGuard(database),
        clock=lambda: 1_900_000_000,
    )
    adapter = CountingAdapter()
    with pytest.raises(AuthorizationError, match="revoked"):
        gateway.execute(chain, signed_request, adapter)
    assert adapter.calls == 0
