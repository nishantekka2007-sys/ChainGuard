"""SQLite-backed persistent security state for ChainGuard's single-host prototype."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from chainguard.core import AuthorizationError, Capability
from chainguard.identity import IdentityRegistry
from chainguard.revocation import RevocationRegistry


def _validate_public_key(public_key: bytes) -> None:
    if not isinstance(public_key, bytes):
        raise AuthorizationError("Public key must be raw Ed25519 bytes.")
    try:
        Ed25519PublicKey.from_public_bytes(public_key)
    except (ValueError, TypeError) as exc:
        raise AuthorizationError("Invalid Ed25519 public key.") from exc


class SQLiteStateStore:
    """Initialize a SQLite file shared by persistent ChainGuard registries."""

    def __init__(self, database: str | Path, *, timeout: float = 10.0) -> None:
        if not isinstance(database, (str, Path)) or not str(database).strip():
            raise AuthorizationError("A database file path is required.")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise AuthorizationError("Database timeout must be a positive number.")
        self.database = str(database)
        if self.database == ":memory:":
            raise AuthorizationError("A database file path is required for shared persistent state.")
        self.timeout = float(timeout)
        path = Path(self.database).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.database = str(path)

        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
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
                    active INTEGER NOT NULL DEFAULT 1,
                    registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    deactivated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS identity_key_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identity TEXT NOT NULL,
                    previous_public_key BLOB NOT NULL,
                    replacement_public_key BLOB NOT NULL,
                    changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
            columns = {
                row[1] for row in connection.execute(
                    "PRAGMA table_info(trusted_identities)"
                ).fetchall()
            }
            if "active" not in columns:
                connection.execute(
                    "ALTER TABLE trusted_identities ADD COLUMN active INTEGER NOT NULL DEFAULT 1"
                )
            if "deactivated_at" not in columns:
                connection.execute(
                    "ALTER TABLE trusted_identities ADD COLUMN deactivated_at TEXT"
                )
            connection.execute(
                "UPDATE schema_metadata SET value = '2' WHERE key = 'schema_version'"
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
    """Persistent identity registry with key rotation and deactivation."""

    def __init__(self, database: str | Path, *, timeout: float = 10.0) -> None:
        super().__init__()
        self.store = SQLiteStateStore(database, timeout=timeout)

    def register(self, identity: str, public_key: bytes) -> None:
        if not isinstance(identity, str) or not identity.strip():
            raise AuthorizationError("Identity must be a non-empty string.")
        _validate_public_key(public_key)
        try:
            with self.store.connect() as connection:
                connection.execute(
                    "INSERT INTO trusted_identities(identity, public_key, active) VALUES (?, ?, 1)",
                    (identity.strip(), sqlite3.Binary(public_key)),
                )
        except sqlite3.IntegrityError as exc:
            raise AuthorizationError("Identity is already registered.") from exc

    def get_public_key(self, identity: str) -> bytes | None:
        if not isinstance(identity, str):
            return None
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT public_key FROM trusted_identities WHERE identity = ? AND active = 1",
                (identity.strip(),),
            ).fetchone()
        return bytes(row[0]) if row else None

    def is_registered(self, identity: str) -> bool:
        return self.get_public_key(identity) is not None

    def rotate_key(self, identity: str, new_public_key: bytes) -> None:
        """Atomically replace an identity key and record the old/new public keys.

        Capabilities signed by the previous key stop verifying immediately
        after the rotation commits.
        """
        if not isinstance(identity, str) or not identity.strip():
            raise AuthorizationError("Identity must be a non-empty string.")
        _validate_public_key(new_public_key)
        identity = identity.strip()
        try:
            with self.store.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT public_key FROM trusted_identities WHERE identity = ?",
                    (identity,),
                ).fetchone()
                if row is None:
                    raise AuthorizationError("Identity is not registered.")
                old_public_key = bytes(row[0])
                if old_public_key == new_public_key:
                    raise AuthorizationError("Replacement key must differ from the current key.")
                connection.execute(
                    """
                    INSERT INTO identity_key_history(
                        identity, previous_public_key, replacement_public_key
                    ) VALUES (?, ?, ?)
                    """,
                    (identity, sqlite3.Binary(old_public_key), sqlite3.Binary(new_public_key)),
                )
                connection.execute(
                    """
                    UPDATE trusted_identities
                    SET public_key = ?, active = 1, deactivated_at = NULL
                    WHERE identity = ?
                    """,
                    (sqlite3.Binary(new_public_key), identity),
                )
        except sqlite3.Error as exc:
            raise AuthorizationError("Persistent identity state is unavailable.") from exc

    def deactivate(self, identity: str) -> None:
        """Disable an identity so all capabilities signed by its key fail closed."""
        if not isinstance(identity, str) or not identity.strip():
            raise AuthorizationError("Identity must be a non-empty string.")
        identity = identity.strip()
        try:
            with self.store.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT 1 FROM trusted_identities WHERE identity = ?",
                    (identity,),
                ).fetchone()
                if row is None:
                    raise AuthorizationError("Identity is not registered.")
                connection.execute(
                    """
                    UPDATE trusted_identities
                    SET active = 0, deactivated_at = CURRENT_TIMESTAMP
                    WHERE identity = ?
                    """,
                    (identity,),
                )
        except sqlite3.Error as exc:
            raise AuthorizationError("Persistent identity state is unavailable.") from exc


class SQLiteRevocationRegistry(RevocationRegistry):
    """Persistent ancestor-aware revocation records."""

    def __init__(self, database: str | Path, *, timeout: float = 10.0) -> None:
        super().__init__()
        self.store = SQLiteStateStore(database, timeout=timeout)

    def revoke(self, capability: Capability) -> None:
        if not isinstance(capability, Capability):
            raise AuthorizationError("A valid capability is required.")
        if not isinstance(capability.capability_id, str) or not capability.capability_id:
            raise AuthorizationError("Capability ID must be a non-empty string.")
        try:
            with self.store.connect() as connection:
                connection.execute(
                    "INSERT OR IGNORE INTO revoked_capabilities(capability_id) VALUES (?)",
                    (capability.capability_id,),
                )
        except sqlite3.Error as exc:
            raise AuthorizationError("Persistent revocation state is unavailable.") from exc

    def is_revoked(self, capability: Capability) -> bool:
        if not isinstance(capability, Capability):
            raise AuthorizationError("A valid capability is required.")
        lineage = capability.ancestor_ids + (capability.capability_id,)
        if not lineage:
            return False
        placeholders = ",".join("?" for _ in lineage)
        try:
            with self.store.connect() as connection:
                row = connection.execute(
                    f"SELECT 1 FROM revoked_capabilities WHERE capability_id IN ({placeholders}) LIMIT 1",
                    lineage,
                ).fetchone()
        except sqlite3.Error as exc:
            raise AuthorizationError("Persistent revocation state is unavailable.") from exc
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
        except sqlite3.Error as exc:
            raise AuthorizationError("Persistent replay state is unavailable.") from exc
