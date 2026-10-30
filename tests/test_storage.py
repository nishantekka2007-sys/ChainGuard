from concurrent.futures import ThreadPoolExecutor
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.core import AuthorizationError, delegate, issue_root_capability
from chainguard.integrity import sign_capability
from chainguard.verification import verify_capability_issuer
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



def test_key_rotation_invalidates_old_signatures_and_accepts_new_key(tmp_path):
    database = tmp_path / "state.sqlite3"
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    registry = SQLiteIdentityRegistry(database)
    registry.register("human", old_key.public_key().public_bytes_raw())
    capability = issue_root_capability("human", "agent-a", {"read"}, {"report"})
    old_signature = sign_capability(capability, old_key)

    registry.rotate_key("human", new_key.public_key().public_bytes_raw())
    with sqlite3.connect(database) as connection:
        history_count = connection.execute("SELECT COUNT(*) FROM identity_key_history").fetchone()[0]
    assert history_count == 1
    reopened = SQLiteIdentityRegistry(database)

    assert not verify_capability_issuer(old_signature, reopened)
    assert verify_capability_issuer(sign_capability(capability, new_key), reopened)


def test_deactivated_identity_cannot_verify_existing_capabilities(tmp_path):
    database = tmp_path / "state.sqlite3"
    key = Ed25519PrivateKey.generate()
    registry = SQLiteIdentityRegistry(database)
    registry.register("human", key.public_key().public_bytes_raw())
    capability = issue_root_capability("human", "agent-a", {"read"}, {"report"})
    signed = sign_capability(capability, key)

    registry.deactivate("human")

    assert not registry.is_registered("human")
    assert registry.get_public_key("human") is None
    assert not verify_capability_issuer(signed, SQLiteIdentityRegistry(database))


def test_key_rotation_rejects_unknown_identity_and_same_key(tmp_path):
    registry = SQLiteIdentityRegistry(tmp_path / "state.sqlite3")
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes_raw()

    with pytest.raises(AuthorizationError, match="not registered"):
        registry.rotate_key("unknown", public_key)

    registry.register("agent-a", public_key)
    with pytest.raises(AuthorizationError, match="must differ"):
        registry.rotate_key("agent-a", public_key)



def test_store_migrates_existing_identity_table_without_active_column(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE trusted_identities (identity TEXT PRIMARY KEY, public_key BLOB NOT NULL, registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        connection.execute(
            "INSERT INTO trusted_identities(identity, public_key) VALUES (?, ?)",
            ("legacy-agent", key),
        )

    registry = SQLiteIdentityRegistry(database)
    assert registry.get_public_key("legacy-agent") == key
    registry.deactivate("legacy-agent")
    assert not registry.is_registered("legacy-agent")



def test_identity_lookup_fails_closed_when_database_schema_is_unavailable(tmp_path):
    database = tmp_path / "state.sqlite3"
    registry = SQLiteIdentityRegistry(database)
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    registry.register("agent-a", key)

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE trusted_identities")

    with pytest.raises(AuthorizationError, match="Persistent identity state"):
        registry.get_public_key("agent-a")
