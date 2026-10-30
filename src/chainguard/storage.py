"""SQLite-backed persistent state for ChainGuard's single-host prototype.

This module provides durable identity, revocation, and replay records shared
between processes using one SQLite database file. It is not a distributed
consensus service and does not make revocation plus an external side effect
atomic.
"""

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from collections.abc import Iterator

from chainguard.core import AuthorizationError, Capability
from chainguard.identity import IdentityRegistry
from chainguard.revocation import RevocationRegistry
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class SQLiteStateStore:
    """Initialize and expose a SQLite database for persistent security state."""

    def __init__(self, database: str | Path, *, timeout: float = 10.0) -> None:
        if not isinstance(database, (str, Path)) or not str(database).strip():
            raise AuthorizationError("A database file path is required.")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise AuthorizationError("Database timeout must be a positive number.")

        self.database = str(database)
        self.timeout = float(timeout)
        if self.database == ":memory:":
            raise AuthorizationError("A database file path is required for shared persistent state.")
        if self.database != ":memory:":
            path = Path(self.database).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            self.database = str(path)

        with self.connect() as connection:
            # Multiple processes may initialize registries against the same new
            # database simultaneously. WAL mode is an optimization, not a
            # correctness requirement; another initializer may hold the schema
            # lock while this connection requests the journal-mode transition.
            try:
                connection.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO schema_metadata(key, value)
                    VALUES ('schema_version', '1');

                CREATE TABLE IF NOT EXISTS trusted_identities (
                    identity TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS revoked_capabilities (
                    capability_id TEXT PRIMARY KEY,
                    revoked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS consumed_requests (
                    request_id TEXT PRIMARY KEY,
                    consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a configured connection and always close it after the transaction."""
        connection = sqlite3.connect(self.database, timeout=self.timeout)
        try:
            connection.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)}")
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class SQLiteIdentityRegistry(IdentityRegistry):
    """Identity registry whose trusted public keys survive process restarts."""

    def __init__(self, database: str | Path, *, timeout: float = 10.0) -> None:
        super().__init__()
        self.store = SQLiteStateStore(database, timeout=timeout)

    def register(self, identity: str, public_key: bytes) -> None:
        if not isinstance(identity, str) or not identity.strip():
            raise AuthorizationError("Identity must be a non-empty string.")
        if not isinstance(public_key, bytes):
            raise AuthorizationError("Public key must be raw Ed25519 bytes.")
        try:
            Ed25519PublicKey.from_public_bytes(public_key)
        except (ValueError, TypeError) as exc:
            raise AuthorizationError("Invalid Ed25519 public key.") from exc

        try:
            with self.store.connect() as connection:
                connection.execute(
                    "INSERT INTO trusted_identities(identity, public_key) VALUES (?, ?)",
                    (identity.strip(), sqlite3.Binary(public_key)),
                )
        except sqlite3.IntegrityError as exc:
            raise AuthorizationError("Identity is already registered.") from exc

    def get_public_key(self, identity: str) -> bytes | None:
        if not isinstance(identity, str):
            return None
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT public_key FROM trusted_identities WHERE identity = ?",
                (identity.strip(),),
            ).fetchone()
        return bytes(row[0]) if row else None

    def is_registered(self, identity: str) -> bool:
        return self.get_public_key(identity) is not None


class SQLiteRevocationRegistry(RevocationRegistry):
    """Persistent ancestor-aware revocation records in a SQLite database."""

    def __init__(self, database: str | Path, *, timeout: float = 10.0) -> None:
        super().__init__()
        self.store = SQLiteStateStore(database, timeout=timeout)

    def revoke(self, capability: Capability) -> None:
        if not isinstance(capability, Capability):
            raise AuthorizationError("A valid capability is required.")
        if not isinstance(capability.capability_id, str) or not capability.capability_id:
            raise AuthorizationError("Capability ID must be a non-empty string.")
        with self.store.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO revoked_capabilities(capability_id) VALUES (?)",
                (capability.capability_id,),
            )

    def is_revoked(self, capability: Capability) -> bool:
        if not isinstance(capability, Capability):
            raise AuthorizationError("A valid capability is required.")
        lineage = capability.ancestor_ids + (capability.capability_id,)
        if not lineage:
            return False
        placeholders = ",".join("?" for _ in lineage)
        with self.store.connect() as connection:
            row = connection.execute(
                f"SELECT 1 FROM revoked_capabilities WHERE capability_id IN ({placeholders}) LIMIT 1",
                lineage,
            ).fetchone()
        return row is not None


class SQLiteReplayGuard:
    """Durable replay guard shared by gateway instances using the same DB."""

    def __init__(self, database: str | Path, *, timeout: float = 10.0) -> None:
        self.store = SQLiteStateStore(database, timeout=timeout)

    def consume(self, request_id: str) -> None:
        if not isinstance(request_id, str) or not request_id.strip():
            raise AuthorizationError("Request ID must be a non-empty string.")
        try:
            with self.store.connect() as connection:
                connection.execute(
                    "INSERT INTO consumed_requests(request_id) VALUES (?)",
                    (request_id.strip(),),
                )
        except sqlite3.IntegrityError as exc:
            raise AuthorizationError("Request replay detected.") from exc
