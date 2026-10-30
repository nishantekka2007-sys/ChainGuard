"""Tests for single-host, transactionally ordered authorization admission."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from chainguard.core import AuthorizationError, issue_root_capability
from chainguard.gateway import ActionRequest, EnforcementGateway, sign_action_request
from chainguard.integrity import sign_capability
from chainguard.storage import (
    SQLiteAdmissionCoordinator,
    SQLiteIdentityRegistry,
    SQLiteReplayGuard,
    SQLiteRevocationRegistry,
)


class Adapter:
    def __init__(self):
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return "executed"


def setup(tmp_path):
    database = tmp_path / "state.sqlite3"
    human_key = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    identities = SQLiteIdentityRegistry(database)
    identities.register("human", human_key.public_key().public_bytes_raw())
    identities.register("agent", agent_key.public_key().public_bytes_raw())
    capability = issue_root_capability(
        "human", "agent", {"read"}, {"report"},
        audience="report-service", workflow_id="workflow-1",
        expires_at=2_000_000_000,
    )
    chain = (sign_capability(capability, human_key),)
    request = ActionRequest(
        "admission-request-1", "agent", "read", "report",
        "report-service", "workflow-1",
    )
    signed = sign_action_request(request, agent_key)
    gateway = EnforcementGateway(
        identities,
        SQLiteRevocationRegistry(database),
        replay_guard=SQLiteReplayGuard(database),
        clock=lambda: 1_900_000_000,
        admission_coordinator=SQLiteAdmissionCoordinator(database),
    )
    return database, capability, chain, signed, gateway


def test_revocation_committed_before_admission_is_rejected(tmp_path):
    database, capability, chain, signed, gateway = setup(tmp_path)
    SQLiteRevocationRegistry(database).revoke(capability)
    adapter = Adapter()

    with pytest.raises(AuthorizationError, match="revoked"):
        gateway.execute(chain, signed, adapter)

    assert adapter.calls == 0


def test_revoke_after_admission_does_not_cancel_admitted_request(tmp_path):
    database, capability, chain, signed, gateway = setup(tmp_path)

    class RevokeImmediatelyBeforeAdapter:
        def admit(self, admitted_capability, request_id):
            SQLiteAdmissionCoordinator(database).admit(
                admitted_capability, request_id
            )
            # The admission transaction has committed; adapter invocation is next.
            SQLiteRevocationRegistry(database).revoke(capability)

    gateway._admission_coordinator = RevokeImmediatelyBeforeAdapter()
    adapter = Adapter()
    assert gateway.execute(chain, signed, adapter) == "executed"
    assert adapter.calls == 1
    assert SQLiteRevocationRegistry(database).is_revoked(capability)


def test_admission_and_replay_consumption_are_atomic(tmp_path):
    database, capability, chain, signed, gateway = setup(tmp_path)
    adapter = Adapter()

    assert gateway.execute(chain, signed, adapter) == "executed"
    with pytest.raises(AuthorizationError, match="replay"):
        gateway.execute(chain, signed, adapter)
    assert adapter.calls == 1


def test_sqlite_admission_coordinator_is_shared_across_instances(tmp_path):
    database, capability, chain, signed, gateway = setup(tmp_path)
    coordinator_a = SQLiteAdmissionCoordinator(database)
    coordinator_b = SQLiteAdmissionCoordinator(database)

    coordinator_a.admit(capability, "shared-id")
    with pytest.raises(AuthorizationError, match="replay"):
        coordinator_b.admit(capability, "shared-id")
