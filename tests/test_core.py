import pytest

from chainguard.core import (
    AuthorizationError,
    delegate,
    issue_root_capability,
)


@pytest.fixture
def root_capability():
    return issue_root_capability(
        human="human-001",
        first_agent="finance-agent",
        actions={"read", "calculate"},
        resources={"invoice-001", "invoice-002"},
    )


def test_root_capability_preserves_human_authority():
    capability = issue_root_capability(
        human="human-001",
        first_agent="finance-agent",
        actions={"read"},
        resources={"invoice-001"},
    )

    assert capability.root_principal == "human-001"
    assert capability.issuer == "human-001"
    assert capability.subject == "finance-agent"
    assert capability.parent_id is None
    assert capability.ancestor_ids == ()


def test_legitimate_delegation_reduces_scope(root_capability):
    child = delegate(
        parent=root_capability,
        delegator="finance-agent",
        new_subject="analysis-agent",
        actions={"read"},
        resources={"invoice-001"},
    )

    assert child.root_principal == "human-001"
    assert child.issuer == "finance-agent"
    assert child.subject == "analysis-agent"
    assert child.actions == frozenset({"read"})
    assert child.resources == frozenset({"invoice-001"})
    assert child.parent_id == root_capability.capability_id
    assert child.ancestor_ids == (root_capability.capability_id,)


def test_rejects_unauthorized_action(root_capability):
    with pytest.raises(AuthorizationError, match="unauthorized action"):
        delegate(root_capability, "finance-agent", "payment-agent",
                 {"transfer_money"}, {"invoice-001"})


def test_rejects_unauthorized_resource(root_capability):
    with pytest.raises(AuthorizationError, match="unauthorized resource"):
        delegate(root_capability, "finance-agent", "external-agent",
                 {"read"}, {"bank-account-001"})


def test_rejects_wrong_delegator(root_capability):
    with pytest.raises(AuthorizationError, match="authorized subject"):
        delegate(root_capability, "unknown-agent", "another-agent",
                 {"read"}, {"invoice-001"})


def test_scope_restrictions_survive_multiple_hops(root_capability):
    agent_b = delegate(root_capability, "finance-agent", "agent-b",
                       {"read", "calculate"}, {"invoice-001"})
    agent_c = delegate(agent_b, "agent-b", "agent-c",
                       {"read"}, {"invoice-001"})

    assert agent_c.actions <= agent_b.actions <= root_capability.actions
    assert agent_c.resources <= agent_b.resources <= root_capability.resources
    assert agent_c.root_principal == root_capability.root_principal
    assert agent_c.ancestor_ids == (
        root_capability.capability_id,
        agent_b.capability_id,
    )


def test_rejects_escalation_at_later_hop(root_capability):
    agent_b = delegate(root_capability, "finance-agent", "agent-b",
                       {"read"}, {"invoice-001"})

    with pytest.raises(AuthorizationError, match="unauthorized action"):
        delegate(agent_b, "agent-b", "agent-c",
                 {"calculate"}, {"invoice-001"})


@pytest.mark.parametrize(
    ("actions", "resources"),
    [
        (set(), {"invoice-001"}),
        ({"read"}, set()),
        ({""}, {"invoice-001"}),
        ({"read"}, {""}),
    ],
)
def test_rejects_empty_or_invalid_scope(root_capability, actions, resources):
    with pytest.raises(AuthorizationError):
        delegate(root_capability, "finance-agent", "agent-b",
                 actions, resources)


def test_capability_is_immutable(root_capability):
    with pytest.raises(AttributeError):
        root_capability.subject = "attacker"


def test_delegation_inherits_context_and_cannot_extend_expiry():
    root = issue_root_capability(
        "human-001",
        "agent-a",
        {"read", "summarize"},
        {"report-001"},
        audience="report-service",
        workflow_id="review-2026",
        expires_at=2_000_000_000,
    )
    child = delegate(root, "agent-a", "agent-b", {"read"}, {"report-001"})

    assert child.audience == root.audience
    assert child.workflow_id == root.workflow_id
    assert child.expires_at == root.expires_at
