import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import AuthorizationError
from chainguard.identity import IdentityRegistry


def raw_public_key(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_register_and_retrieve_identity_key():
    private_key = Ed25519PrivateKey.generate()
    registry = IdentityRegistry()
    public_key = raw_public_key(private_key)

    registry.register("agent-a", public_key)

    assert registry.is_registered("agent-a")
    assert registry.get_public_key("agent-a") == public_key


def test_unknown_identity_has_no_trusted_key():
    registry = IdentityRegistry()

    assert not registry.is_registered("unknown-agent")
    assert registry.get_public_key("unknown-agent") is None


def test_duplicate_registration_cannot_replace_key():
    registry = IdentityRegistry()
    first = raw_public_key(Ed25519PrivateKey.generate())
    second = raw_public_key(Ed25519PrivateKey.generate())
    registry.register("agent-a", first)

    with pytest.raises(AuthorizationError, match="already registered"):
        registry.register("agent-a", second)

    assert registry.get_public_key("agent-a") == first


@pytest.mark.parametrize(
    ("identity", "public_key"),
    [
        ("", b"not-a-key"),
        ("agent-a", b"not-a-key"),
        ("   ", raw_public_key(Ed25519PrivateKey.generate())),
    ],
)
def test_invalid_registration_is_rejected(identity, public_key):
    registry = IdentityRegistry()

    with pytest.raises(AuthorizationError):
        registry.register(identity, public_key)
