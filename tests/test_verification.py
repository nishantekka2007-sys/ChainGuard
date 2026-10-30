from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import delegate, issue_root_capability
from chainguard.identity import IdentityRegistry
from chainguard.integrity import sign_capability
from chainguard.verification import (
    verify_capability_issuer,
    verify_delegation_chain,
)


def setup_chain():
    human_key = Ed25519PrivateKey.generate()
    agent_a_key = Ed25519PrivateKey.generate()
    agent_b_key = Ed25519PrivateKey.generate()

    registry = IdentityRegistry()
    registry.register(
        "human-001",
        human_key.public_key().public_bytes_raw(),
    )
    registry.register(
        "agent-a",
        agent_a_key.public_key().public_bytes_raw(),
    )
    registry.register(
        "agent-b",
        agent_b_key.public_key().public_bytes_raw(),
    )

    root = issue_root_capability(
        "human-001", "agent-a",
        {"read", "summarize"}, {"report-001", "report-002"},
    )
    child = delegate(
        root, "agent-a", "agent-b",
        {"read"}, {"report-001"},
    )

    signed_root = sign_capability(root, human_key)
    signed_child = sign_capability(child, agent_a_key)
    return registry, human_key, agent_a_key, root, child, signed_root, signed_child


def test_valid_root_and_delegated_chain_verifies():
    registry, _, _, _, _, signed_root, signed_child = setup_chain()

    assert verify_delegation_chain([signed_root, signed_child], registry)


def test_issuer_signature_must_match_registered_identity():
    registry, _, _, _, child, _, _ = setup_chain()
    forged = sign_capability(child, Ed25519PrivateKey.generate())

    assert not verify_capability_issuer(forged, registry)


def test_unregistered_issuer_is_rejected():
    registry, _, _, root, _, _, _ = setup_chain()
    unknown_key = Ed25519PrivateKey.generate()
    forged_root = replace(root, issuer="unknown-human")
    signed = sign_capability(forged_root, unknown_key)

    assert not verify_capability_issuer(signed, registry)


def test_valid_signature_does_not_authorize_scope_escalation():
    registry, _, agent_a_key, _, child, signed_root, _ = setup_chain()
    escalated = replace(
        child,
        actions=frozenset({"read", "transfer_money"}),
    )
    signed_escalated = sign_capability(escalated, agent_a_key)

    assert verify_capability_issuer(signed_escalated, registry)
    assert not verify_delegation_chain(
        [signed_root, signed_escalated], registry
    )


def test_wrong_parent_link_is_rejected():
    registry, _, agent_a_key, _, child, signed_root, _ = setup_chain()
    forged = replace(child, parent_id="unrelated-parent")
    signed_forged = sign_capability(forged, agent_a_key)

    assert not verify_delegation_chain([signed_root, signed_forged], registry)


def test_wrong_delegating_issuer_is_rejected():
    registry, _, agent_a_key, _, child, signed_root, _ = setup_chain()
    forged = replace(child, issuer="human-001")
    signed_forged = sign_capability(forged, agent_a_key)

    assert not verify_delegation_chain([signed_root, signed_forged], registry)


def test_resource_escalation_is_rejected_even_with_valid_signature():
    registry, _, agent_a_key, _, child, signed_root, _ = setup_chain()
    forged = replace(
        child,
        resources=frozenset({"report-001", "secret-payroll"}),
    )
    signed_forged = sign_capability(forged, agent_a_key)

    assert not verify_delegation_chain([signed_root, signed_forged], registry)


def test_malformed_capability_object_is_rejected_without_exception():
    registry, _, _, _, _, signed_root, _ = setup_chain()
    malformed = replace(signed_root, capability=object())

    assert not verify_capability_issuer(malformed, registry)
    assert not verify_delegation_chain([malformed], registry)


def test_duplicate_capability_ids_in_chain_are_rejected():
    registry, _, agent_a_key, root, _, signed_root, _ = setup_chain()
    duplicate = replace(
        root,
        issuer="agent-a",
        subject="agent-b",
        parent_id=root.capability_id,
        ancestor_ids=(root.capability_id,),
    )
    signed_duplicate = sign_capability(duplicate, agent_a_key)

    assert not verify_delegation_chain(
        [signed_root, signed_duplicate], registry
    )
