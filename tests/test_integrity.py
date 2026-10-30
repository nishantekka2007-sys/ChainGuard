from dataclasses import replace

import pytest

from chainguard.core import AuthorizationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import delegate, issue_root_capability
from chainguard.integrity import sign_capability, verify_signed_capability


@pytest.fixture
def keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_key


@pytest.fixture
def capability():
    return issue_root_capability(
        human="human-001",
        first_agent="research-agent",
        actions={"read", "summarize"},
        resources={"report-001"},
    )


def test_valid_signature_verifies(capability, keypair):
    private_key, public_key = keypair
    signed = sign_capability(capability, private_key)

    assert verify_signed_capability(signed, public_key)


def test_modified_action_is_detected(capability, keypair):
    private_key, public_key = keypair
    signed = sign_capability(capability, private_key)
    modified = replace(
        capability,
        actions=frozenset({"read", "transfer_money"}),
    )

    assert not verify_signed_capability(
        replace(signed, capability=modified),
        public_key,
    )


def test_modified_subject_is_detected(capability, keypair):
    private_key, public_key = keypair
    signed = sign_capability(capability, private_key)
    modified = replace(capability, subject="attacker-agent")

    assert not verify_signed_capability(
        replace(signed, capability=modified),
        public_key,
    )


def test_modified_delegation_parent_is_detected(capability, keypair):
    private_key, public_key = keypair
    child = delegate(
        capability, "research-agent", "summary-agent",
        {"read"}, {"report-001"},
    )
    signed = sign_capability(child, private_key)
    modified = replace(child, parent_id="forged-parent-id")

    assert not verify_signed_capability(
        replace(signed, capability=modified),
        public_key,
    )


def test_untrusted_signer_key_is_rejected(capability, keypair):
    private_key, _ = keypair
    signed = sign_capability(capability, private_key)
    attacker_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    assert not verify_signed_capability(signed, attacker_key)


def test_signature_bytes_tampering_is_rejected(capability, keypair):
    private_key, public_key = keypair
    signed = sign_capability(capability, private_key)
    corrupted = bytes([signed.signature[0] ^ 1]) + signed.signature[1:]

    assert not verify_signed_capability(
        replace(signed, signature=corrupted),
        public_key,
    )


def test_signing_requires_ed25519_private_key(capability):
    with pytest.raises(AuthorizationError, match="Ed25519 private key"):
        sign_capability(capability, object())
