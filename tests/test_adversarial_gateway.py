"""Adversarial tests for the ChainGuard authorization boundary.

Each attack test asserts both rejection and the absence of protected adapter
execution. These tests exercise the prototype boundary; they do not establish
infrastructure-level bypass resistance.
"""
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import AuthorizationError, delegate, issue_root_capability
from chainguard.gateway import (
    ActionRequest,
    EnforcementGateway,
    sign_action_request,
)
from chainguard.identity import IdentityRegistry
from chainguard.integrity import sign_capability
from chainguard.revocation import RevocationRegistry


class RecordingAdapter:
    def __init__(self):
        self.calls = []

    def execute(self, request):
        self.calls.append(request)
        return "executed"


@pytest.fixture
def attack_environment():
    human_key = Ed25519PrivateKey.generate()
    agent_a_key = Ed25519PrivateKey.generate()
    agent_b_key = Ed25519PrivateKey.generate()
    identities = IdentityRegistry()
    identities.register("human", human_key.public_key().public_bytes_raw())
    identities.register("agent-a", agent_a_key.public_key().public_bytes_raw())
    identities.register("agent-b", agent_b_key.public_key().public_bytes_raw())

    root = issue_root_capability(
        "human", "agent-a", {"read", "summarize"}, {"report-a", "report-b"},
        audience="report-service", workflow_id="workflow-7", expires_at=2_000_000_000,
    )
    child = delegate(root, "agent-a", "agent-b", {"read"}, {"report-a"})
    chain = (sign_capability(root, human_key), sign_capability(child, agent_a_key))
    gateway = EnforcementGateway(
        identities, RevocationRegistry(), clock=lambda: 1_900_000_000
    )
    request = ActionRequest(
        "attack-request-1", "agent-b", "read", "report-a",
        "report-service", "workflow-7",
    )
    signed_request = sign_action_request(request, agent_b_key)
    return {
        "gateway": gateway,
        "identities": identities,
        "revocations": gateway._revocations,
        "root": root,
        "child": child,
        "chain": chain,
        "agent_b_key": agent_b_key,
        "request": request,
        "signed_request": signed_request,
    }


def assert_denied_before_adapter(environment, chain=None, signed_request=None, gateway=None):
    adapter = RecordingAdapter()
    active_gateway = gateway or environment["gateway"]
    with pytest.raises(AuthorizationError):
        active_gateway.execute(
            chain if chain is not None else environment["chain"],
            signed_request if signed_request is not None else environment["signed_request"],
            adapter,
        )
    assert adapter.calls == []


def test_tampered_action_after_signing_is_rejected(attack_environment):
    env = attack_environment
    tampered = replace(
        env["signed_request"],
        request=replace(env["request"], action="delete"),
    )
    assert_denied_before_adapter(env, signed_request=tampered)


def test_tampered_resource_after_signing_is_rejected(attack_environment):
    env = attack_environment
    tampered = replace(
        env["signed_request"],
        request=replace(env["request"], resource="payroll"),
    )
    assert_denied_before_adapter(env, signed_request=tampered)


def test_untrusted_signer_key_substitution_is_rejected(attack_environment):
    env = attack_environment
    attacker_key = Ed25519PrivateKey.generate()
    forged = sign_action_request(env["request"], attacker_key)
    assert_denied_before_adapter(env, signed_request=forged)


def test_modified_request_signature_is_rejected(attack_environment):
    env = attack_environment
    signature = bytearray(env["signed_request"].signature)
    signature[0] ^= 0x01
    tampered = replace(env["signed_request"], signature=bytes(signature))
    assert_denied_before_adapter(env, signed_request=tampered)


def test_capability_mutation_after_signing_is_rejected(attack_environment):
    env = attack_environment
    root_signed, child_signed = env["chain"]
    altered_child = replace(
        child_signed,
        capability=replace(child_signed.capability, actions=frozenset({"read", "delete"})),
    )
    assert_denied_before_adapter(env, chain=(root_signed, altered_child))


def test_reordered_delegation_chain_is_rejected(attack_environment):
    env = attack_environment
    assert_denied_before_adapter(env, chain=tuple(reversed(env["chain"])))


def test_truncated_chain_cannot_authorize_downstream_subject(attack_environment):
    env = attack_environment
    assert_denied_before_adapter(env, chain=(env["chain"][0],))


def test_revoked_leaf_is_rejected(attack_environment):
    env = attack_environment
    env["revocations"].revoke(env["child"])
    assert_denied_before_adapter(env)


def test_capability_is_expired_at_exact_expiry_boundary(attack_environment):
    env = attack_environment
    expiry_gateway = EnforcementGateway(
        env["identities"], env["revocations"],
        clock=lambda: env["child"].expires_at,
    )
    assert_denied_before_adapter(env, gateway=expiry_gateway)


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", ""),
        ("actor", " "),
        ("action", ""),
        ("resource", ""),
        ("audience", ""),
        ("workflow_id", ""),
    ],
)
def test_empty_request_fields_are_rejected_before_adapter(attack_environment, field, value):
    env = attack_environment
    malformed_request = replace(env["request"], **{field: value})
    # A malformed request cannot be signed through the public helper, so wrap
    # the existing signature around the changed request to exercise the gateway.
    malformed_signed = replace(env["signed_request"], request=malformed_request)
    assert_denied_before_adapter(env, signed_request=malformed_signed)


def test_adapter_is_not_called_when_adapter_contract_is_invalid(attack_environment):
    env = attack_environment
    with pytest.raises(AuthorizationError, match="adapter"):
        env["gateway"].execute(env["chain"], env["signed_request"], object())
