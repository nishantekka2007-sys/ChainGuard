from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import AuthorizationError, delegate, issue_root_capability
from chainguard.storage import (
    SQLiteIdentityRegistry,
    SQLiteReplayGuard,
    SQLiteRevocationRegistry,
)


def test_identity_registry_persists_keys_across_instances(tmp_path):
    database = tmp_path / "state.sqlite3"
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()

    first = SQLiteIdentityRegistry(database)
    first.register("agent-a", public_key)

    reopened = SQLiteIdentityRegistry(database)
    assert reopened.get_public_key("agent-a") == public_key
    assert reopened.is_registered("agent-a")


def test_identity_registry_rejects_duplicate_and_invalid_keys(tmp_path):
    database = tmp_path / "state.sqlite3"
    registry = SQLiteIdentityRegistry(database)
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    registry.register("agent-a", key)

    with pytest.raises(AuthorizationError, match="already registered"):
        SQLiteIdentityRegistry(database).register("agent-a", key)

    with pytest.raises(AuthorizationError, match="Invalid Ed25519"):
        registry.register("agent-b", b"not-a-valid-key")


def test_revocation_persists_and_covers_descendants(tmp_path):
    database = tmp_path / "state.sqlite3"
    root = issue_root_capability("human", "agent-a", {"read"}, {"report"})
    child = delegate(root, "agent-a", "agent-b", {"read"}, {"report"})

    SQLiteRevocationRegistry(database).revoke(root)
    reopened = SQLiteRevocationRegistry(database)

    assert reopened.is_revoked(root)
    assert reopened.is_revoked(child)


def test_revoking_child_does_not_revoke_parent(tmp_path):
    database = tmp_path / "state.sqlite3"
    root = issue_root_capability("human", "agent-a", {"read"}, {"report"})
    child = delegate(root, "agent-a", "agent-b", {"read"}, {"report"})

    registry = SQLiteRevocationRegistry(database)
    registry.revoke(child)

    assert not registry.is_revoked(root)
    assert registry.is_revoked(child)


def test_replay_guard_persists_across_instances(tmp_path):
    database = tmp_path / "state.sqlite3"
    SQLiteReplayGuard(database).consume("request-1")

    with pytest.raises(AuthorizationError, match="replay"):
        SQLiteReplayGuard(database).consume("request-1")


def test_replay_guard_allows_only_one_concurrent_consumer_across_instances(tmp_path):
    database = tmp_path / "state.sqlite3"

    def consume():
        try:
            SQLiteReplayGuard(database).consume("shared-request")
            return "accepted"
        except AuthorizationError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: consume(), range(8)))

    assert outcomes.count("accepted") == 1
    assert outcomes.count("rejected") == 7



def test_store_rejects_memory_database_for_multi_connection_state():
    from chainguard.storage import SQLiteStateStore

    with pytest.raises(AuthorizationError, match="database file path"):
        SQLiteStateStore(":memory:")
