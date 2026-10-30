import pytest

from chainguard.core import AuthorizationError, delegate, issue_root_capability
from chainguard.revocation import RevocationRegistry


@pytest.fixture
def chain():
    root = issue_root_capability(
        human="human-001",
        first_agent="agent-a",
        actions={"read", "summarize"},
        resources={"report-001"},
    )
    child = delegate(root, "agent-a", "agent-b",
                     {"read", "summarize"}, {"report-001"})
    grandchild = delegate(child, "agent-b", "agent-c",
                          {"read"}, {"report-001"})
    return root, child, grandchild


def test_new_capabilities_are_active(chain):
    registry = RevocationRegistry()
    for capability in chain:
        registry.require_active(capability)
        assert not registry.is_revoked(capability)


def test_revoking_capability_invalidates_itself(chain):
    _, child, _ = chain
    registry = RevocationRegistry()

    registry.revoke(child)

    assert registry.is_revoked(child)
    with pytest.raises(AuthorizationError, match="revoked"):
        registry.require_active(child)


def test_revoking_parent_invalidates_all_descendants(chain):
    root, child, grandchild = chain
    registry = RevocationRegistry()

    registry.revoke(root)

    assert registry.is_revoked(root)
    assert registry.is_revoked(child)
    assert registry.is_revoked(grandchild)
    with pytest.raises(AuthorizationError, match="revoked"):
        registry.require_active(grandchild)


def test_revoking_child_does_not_revoke_parent_or_sibling(chain):
    root, child, _ = chain
    sibling = delegate(root, "agent-a", "agent-d",
                       {"read"}, {"report-001"})
    registry = RevocationRegistry()

    registry.revoke(child)

    assert not registry.is_revoked(root)
    assert not registry.is_revoked(sibling)
    assert registry.is_revoked(child)


def test_rejects_non_capability_input():
    registry = RevocationRegistry()

    with pytest.raises(AuthorizationError, match="valid capability"):
        registry.revoke("not-a-capability")

    with pytest.raises(AuthorizationError, match="valid capability"):
        registry.is_revoked("not-a-capability")
