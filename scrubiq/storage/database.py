"""SQLite database connection and schema management.

C1 FIX: Supports SQLCipher for encrypted database when available.
Install with: pip install sqlcipher3-binary

Concurrency model:
- Uses read-write lock pattern for better throughput
- Multiple readers can proceed concurrently (WAL mode)
- Writers get exclusive access
- Automatic retry with exponential backoff for lock contention
"""

import sqlite3
import time
import threading
from pathlib import Path
from typing import Optional
from contextlib import contextmanager
import logging

from ..constants import (
    DATABASE_LOCK_TIMEOUT,
    DB_MAX_RETRIES,
    DB_RETRY_BASE_DELAY,
    DB_RETRY_MAX_DELAY,
)

logger = logging.getLogger(__name__)


class ReadWriteLock:
    """
    A read-write lock for better concurrency.

    - Multiple readers can hold the lock simultaneously
    - Writers get exclusive access (no readers or other writers)
    - Writers have priority to prevent starvation

    This improves throughput for read-heavy workloads like token lookups.
    """

    def __init__(self):
        self._read_ready = threading.Condition(threading.Lock())
        self._readers = 0
        self._writers_waiting = 0
        self._writer_active = False

    @contextmanager
    def read_lock(self):
        """Acquire read lock - multiple readers allowed."""
        with self._read_ready:
            # Wait if a writer is active or waiting (writer priority)
            while self._writer_active or self._writers_waiting > 0:
                self._read_ready.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._read_ready:
                self._readers -= 1
                if self._readers == 0:
                    self._read_ready.notify_all()

    @contextmanager
    def write_lock(self):
        """Acquire write lock - exclusive access."""
        with self._read_ready:
            self._writers_waiting += 1
            # Wait until no readers and no active writer
            while self._readers > 0 or self._writer_active:
                self._read_ready.wait()
            self._writers_waiting -= 1
            self._writer_active = True
        try:
            yield
        finally:
            with self._read_ready:
                self._writer_active = False
                self._read_ready.notify_all()


# Try to import SQLCipher - REQUIRED for database encryption
_SQLCIPHER_AVAILABLE = False
try:
    import sqlcipher3
    _SQLCIPHER_AVAILABLE = True
    logger.info("SQLCipher available - database encryption enabled")
except ImportError:
    import os
    # SQLCipher is required unless explicitly opted out (for testing only)
    allow_unencrypted = os.environ.get("SCRUBIQ_ALLOW_UNENCRYPTED_DB", "").lower() in ("1", "true", "yes")

    if not allow_unencrypted:
        raise RuntimeError(
            "SECURITY ERROR: SQLCipher is required!\n"
            "Database encryption protects session IDs, token patterns, and audit logs.\n\n"
            "Install with:\n"
            "  sudo apt install -y libsqlcipher-dev\n"
            "  pip install sqlcipher3-binary\n\n"
            "For testing ONLY (not recommended):\n"
            "  export SCRUBIQ_ALLOW_UNENCRYPTED_DB=true"
        )

    # Explicit opt-in to unencrypted mode - warn loudly
    logger.warning(
        "=" * 70 + "\n"
        "SECURITY WARNING: Running with UNENCRYPTED database!\n"
        "SCRUBIQ_ALLOW_UNENCRYPTED_DB=true is set.\n"
        "This should ONLY be used for testing. PHI metadata is NOT protected.\n"
        "Install SQLCipher: pip install sqlcipher3-binary\n" +
        "=" * 70
    )

SCHEMA_VERSION = 9

SCHEMA = """
-- Settings (key-value store for app configuration)
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
);

-- API keys for authentication
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_used_at REAL,
    rate_limit INTEGER NOT NULL DEFAULT 1000,
    permissions TEXT NOT NULL DEFAULT '["redact","restore","chat"]',
    revoked_at REAL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

-- Key storage (encrypted DEK, salt, KDF parameters)
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB NOT NULL,
    encrypted_dek BLOB NOT NULL,
    scrypt_n INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Conversations
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT 'New conversation',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_conversations_updated ON conversations(updated_at DESC);

-- Messages (linked to conversation)
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    redacted_content TEXT,
    normalized_content TEXT,
    spans_json TEXT,
    model TEXT,
    provider TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);

-- Token mappings (scoped to session, optionally conversation)
-- Multiple rows per token allowed for variant storage (e.g., "John Smith" and "Smith" → same token)
-- lookup_hash must be unique to ensure each value maps to exactly one token
-- conversation_id allows per-conversation token isolation (empty string = session-wide)
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL DEFAULT '',
    token TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    lookup_hash TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    encrypted_safe_harbor BLOB,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(session_id, conversation_id, lookup_hash)
);

CREATE INDEX IF NOT EXISTS idx_tokens_session ON tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_tokens_conversation ON tokens(session_id, conversation_id);
CREATE INDEX IF NOT EXISTS idx_tokens_lookup ON tokens(session_id, conversation_id, lookup_hash);

-- Audit log with hash chain
CREATE TABLE IF NOT EXISTS audit_log (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    session_id TEXT NOT NULL,
    data TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

-- Encrypted image files (v6)
CREATE TABLE IF NOT EXISTS image_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    file_type TEXT NOT NULL,  -- face_blurred, redacted, redacted_pdf
    encrypted_path TEXT NOT NULL,  -- relative path to .enc file
    original_filename TEXT,
    content_type TEXT NOT NULL,  -- image/png, application/pdf
    sha256_hash TEXT NOT NULL,  -- hash of plaintext for integrity
    size_bytes INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(job_id, file_type)
);

CREATE INDEX IF NOT EXISTS idx_image_files_job ON image_files(job_id);
CREATE INDEX IF NOT EXISTS idx_image_files_session ON image_files(session_id);

-- Memories - extracted facts from conversations (v7)
CREATE TABLE IF NOT EXISTS memories (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    entity_token TEXT,  -- e.g., [PATIENT_1] or NULL for general facts
    fact TEXT NOT NULL,  -- The extracted fact (uses tokens, no PHI)
    category TEXT NOT NULL DEFAULT 'general',  -- medical, preference, action, relationship
    confidence REAL NOT NULL DEFAULT 0.9,
    source_message_id TEXT,  -- Which message this was extracted from
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_memories_conversation ON memories(conversation_id);
CREATE INDEX IF NOT EXISTS idx_memories_entity ON memories(entity_token);
CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category);
CREATE INDEX IF NOT EXISTS idx_memories_created ON memories(created_at DESC);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

-- Auth state (failed attempts, lockout)
CREATE TABLE IF NOT EXISTS auth_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    failed_attempts INTEGER DEFAULT 0,
    locked_until TEXT,
    last_activity TEXT
);
"""


class Database:
    """
    SQLite database manager with optional SQLCipher encryption.

    C1 FIX: When SQLCipher is available and encryption_key is provided,
    the entire database file is encrypted, protecting metadata like
    token patterns, session IDs, and audit logs.

    Thread-safe with read-write lock:
    - Multiple readers can proceed concurrently (WAL mode)
    - Writers get exclusive access
    - Better throughput than simple mutex for read-heavy workloads
    """

    def __init__(self, db_path: Path, encryption_key: Optional[bytes] = None):
        """
        Initialize database.

        Args:
            db_path: Path to database file
            encryption_key: Optional 32-byte key for SQLCipher encryption.
                           If provided and SQLCipher is available, database
                           will be encrypted at rest.
        """
        self.db_path = db_path
        self._encryption_key = encryption_key
        self._conn: Optional[sqlite3.Connection] = None
        self._encrypted = False
        self._rwlock = ReadWriteLock()
        self._conn_lock = threading.Lock()  # Protects connection state changes

    @property
    def is_encrypted(self) -> bool:
        """Check if database is using SQLCipher encryption."""
        return self._encrypted
    
    def _create_connection(self) -> sqlite3.Connection:
        """Create a new database connection."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Use SQLCipher if available and key provided
        if _SQLCIPHER_AVAILABLE and self._encryption_key:
            import sqlcipher3
            conn = sqlcipher3.connect(
                str(self.db_path),
                check_same_thread=False,
                isolation_level="DEFERRED",
                timeout=DATABASE_LOCK_TIMEOUT
            )
            # Set encryption key (hex-encoded for safety)
            key_hex = self._encryption_key.hex()
            conn.execute(f"PRAGMA key = \"x'{key_hex}'\"")
            conn.execute("PRAGMA cipher_memory_security = ON")
            self._encrypted = True
        else:
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                isolation_level="DEFERRED",
                timeout=DATABASE_LOCK_TIMEOUT
            )
            if self._encryption_key and not _SQLCIPHER_AVAILABLE:
                logger.warning(
                    "Encryption key provided but SQLCipher not available. "
                    "Database is NOT encrypted!"
                )

        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")  # 30 second busy timeout
        conn.execute("PRAGMA synchronous = NORMAL")  # Faster with WAL
        
        return conn

    def connect(self) -> None:
        """Open database connection and ensure schema exists."""
        with self._conn_lock:
            self._conn = self._create_connection()
            self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they don't exist.

        Migration order is critical:
        1. Create schema_version table first (to check version)
        2. Check schema version and run migrations if needed
        3. Create/update all tables and indexes (safe after migrations)
        """
        # Step 1: Create schema_version table first so we can check version
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )
        """)

        # Step 2: Check/set schema version and run migrations BEFORE creating indexes
        cur = self._conn.execute("SELECT version FROM schema_version LIMIT 1")
        row = cur.fetchone()
        if row is None:
            # New database - will get full schema
            self._conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
        elif row["version"] != SCHEMA_VERSION:
            # Existing database - run migrations first
            self._migrate(row["version"], SCHEMA_VERSION)

        # Step 3: Now create all tables and indexes (safe after migrations)
        self._conn.executescript(SCHEMA)

        # Ensure auth_state row exists
        self._conn.execute("""
            INSERT OR IGNORE INTO auth_state (id, failed_attempts) VALUES (1, 0)
        """)

        # Commit schema changes
        self._conn.commit()

    def _migrate(self, from_version: int, to_version: int) -> None:
        """
        Run schema migrations.
        
        Raises RuntimeError if migration path not implemented.
        """
        if from_version == to_version:
            return
        
        # Migration from v1 to v2: Add conversations and messages tables
        if from_version == 1 and to_version == 2:
            logger.info("Migrating database schema from v1 to v2...")
            self._conn.executescript("""
                -- Conversations
                CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL DEFAULT 'New conversation',
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_conversations_updated ON conversations(updated_at DESC);
                
                -- Messages
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
                    content TEXT NOT NULL,
                    redacted_content TEXT,
                    model TEXT,
                    provider TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);
            """)
            self._conn.execute("UPDATE schema_version SET version = ?", (to_version,))
            self._conn.commit()
            logger.info("Migration to v2 complete")
            return
        
        # Migration from v2 to v3: Add scrypt_n column to keys table
        if from_version == 2 and to_version == 3:
            logger.info("Migrating database schema from v2 to v3...")
            self._conn.execute("""
                ALTER TABLE keys ADD COLUMN scrypt_n INTEGER
            """)
            self._conn.execute("UPDATE schema_version SET version = ?", (to_version,))
            self._conn.commit()
            logger.info("Migration to v3 complete")
            return
        
        # Migration from v3 to v4: Add spans_json column to messages table
        if from_version == 3 and to_version == 4:
            logger.info("Migrating database schema from v3 to v4...")
            self._conn.execute("""
                ALTER TABLE messages ADD COLUMN spans_json TEXT
            """)
            self._conn.execute("UPDATE schema_version SET version = ?", (to_version,))
            self._conn.commit()
            logger.info("Migration to v4 complete")
            return
        
        # Migration from v4 to v5: Add normalized_content column to messages table
        if from_version == 4 and to_version == 5:
            logger.info("Migrating database schema from v4 to v5...")
            self._conn.execute("""
                ALTER TABLE messages ADD COLUMN normalized_content TEXT
            """)
            self._conn.execute("UPDATE schema_version SET version = ?", (to_version,))
            self._conn.commit()
            logger.info("Migration to v5 complete")
            return
        
        # Migration from v5 to v6: Add image_files table for encrypted image storage
        if from_version == 5 and to_version == 6:
            logger.info("Migrating database schema from v5 to v6...")
            self._conn.executescript("""
                -- Encrypted image files
                CREATE TABLE IF NOT EXISTS image_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    encrypted_path TEXT NOT NULL,
                    original_filename TEXT,
                    content_type TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    session_id TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now')),
                    UNIQUE(job_id, file_type)
                );
                CREATE INDEX IF NOT EXISTS idx_image_files_job ON image_files(job_id);
                CREATE INDEX IF NOT EXISTS idx_image_files_session ON image_files(session_id);
            """)
            self._conn.execute("UPDATE schema_version SET version = ?", (to_version,))
            self._conn.commit()
            logger.info("Migration to v6 complete")
            return
        
        # Migration from v6 to v7: Add memories table and FTS5 index
        if from_version == 6 and to_version == 7:
            logger.info("Migrating database schema from v6 to v7...")
            self._conn.executescript("""
                -- Memories table for extracted facts
                CREATE TABLE IF NOT EXISTS memories (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    entity_token TEXT,
                    fact TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'general',
                    confidence REAL NOT NULL DEFAULT 0.9,
                    source_message_id TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_memories_conversation ON memories(conversation_id);
                CREATE INDEX IF NOT EXISTS idx_memories_entity ON memories(entity_token);
                CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category);
                CREATE INDEX IF NOT EXISTS idx_memories_created ON memories(created_at DESC);
            """)
            self._conn.execute("UPDATE schema_version SET version = ?", (to_version,))
            self._conn.commit()
            logger.info("Migration to v7 complete")
            return

        # Migration from v7 to v8: Add conversation_id to tokens for per-conversation isolation
        if from_version == 7 and to_version == 8:
            logger.info("Migrating database schema from v7 to v8...")
            # Add conversation_id column with empty string default (for session-wide tokens)
            self._conn.execute("""
                ALTER TABLE tokens ADD COLUMN conversation_id TEXT NOT NULL DEFAULT ''
            """)
            # Create new index for conversation-scoped lookups
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tokens_conversation ON tokens(session_id, conversation_id)
            """)
            # Note: SQLite doesn't support DROP CONSTRAINT, but the old constraint
            # UNIQUE(session_id, lookup_hash) is a subset of the new constraint
            # UNIQUE(session_id, conversation_id, lookup_hash). Existing tokens have
            # conversation_id='' so they remain unique. New databases get the full constraint.
            self._conn.execute("UPDATE schema_version SET version = ?", (to_version,))
            self._conn.commit()
            logger.info("Migration to v8 complete")
            return

        # Migration from v8 to v9: Add settings and api_keys tables
        if from_version == 8 and to_version == 9:
            logger.info("Migrating database schema from v8 to v9...")
            self._conn.executescript("""
                -- Settings table for key-value configuration
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                -- API keys for authentication
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_prefix TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_used_at REAL,
                    rate_limit INTEGER NOT NULL DEFAULT 1000,
                    permissions TEXT NOT NULL DEFAULT '["redact","restore","chat"]',
                    revoked_at REAL
                );

                CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
            """)
            self._conn.execute("UPDATE schema_version SET version = ?", (to_version,))
            self._conn.commit()
            logger.info("Migration to v9 complete")
            return

        # Chain migrations to v9
        if from_version < 9 and to_version == 9:
            if from_version < 8:
                self._migrate(from_version, 8)
            self._migrate(8, 9)
            return

        # Chain migrations to v8
        if from_version < 8 and to_version == 8:
            if from_version < 7:
                self._migrate(from_version, 7)
            self._migrate(7, 8)
            return

        # Chain migrations to v7
        if from_version < 7 and to_version == 7:
            if from_version < 6:
                self._migrate(from_version, 6)
            self._migrate(6, 7)
            return
        
        # Chain migrations to v6
        if from_version < 6 and to_version == 6:
            if from_version < 5:
                self._migrate(from_version, 5)
            self._migrate(5, 6)
            return
        
        # Chain migrations to v5 (legacy)
        if from_version < 5 and to_version == 5:
            if from_version < 4:
                self._migrate(from_version, 4)
            self._migrate(4, 5)
            return
        
        # Chain migrations to v4 (legacy)
        if from_version < 4 and to_version == 4:
            if from_version < 3:
                self._migrate(from_version, 3)
            self._migrate(3, 4)
            return
        
        # Chain migrations to v3 (legacy)
        if from_version < 3 and to_version == 3:
            if from_version < 2:
                self._migrate(from_version, 2)
            self._migrate(2, 3)
            return
        
        raise RuntimeError(
            f"No migration path from schema v{from_version} to v{to_version}. "
            "Database may need to be rebuilt."
        )

    def checkpoint(self) -> None:
        """
        Force WAL checkpoint.

        Transfers data from WAL to main database file.
        Useful before backup or when WAL file grows large.

        Note: This should be called when no transactions are active.
        """
        with self._rwlock.write_lock():
            if not self.conn.in_transaction:
                self.conn.execute("PRAGMA wal_checkpoint(PASSIVE)")

    def close(self) -> None:
        """Close database connection."""
        with self._conn_lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        """Get database connection (thread-safe)."""
        with self._conn_lock:
            if self._conn is None:
                raise RuntimeError("Database not connected")
            return self._conn

    def _execute_with_retry(self, func, *args, **kwargs):
        """Execute a database operation with retry logic for locking errors."""
        last_error = None
        delay = DB_RETRY_BASE_DELAY
        
        for attempt in range(DB_MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except sqlite3.OperationalError as e:
                error_msg = str(e).lower()
                if "locked" in error_msg or "busy" in error_msg:
                    last_error = e
                    if attempt < DB_MAX_RETRIES - 1:
                        logger.warning(
                            f"Database locked, retry {attempt + 1}/{DB_MAX_RETRIES} "
                            f"after {delay:.2f}s"
                        )
                        time.sleep(delay)
                        delay = min(delay * 2, DB_RETRY_MAX_DELAY)
                        continue
                raise  # Re-raise non-locking errors immediately
        
        # All retries exhausted
        raise sqlite3.OperationalError(
            f"Database locked after {DB_MAX_RETRIES} retries: {last_error}"
        )

    @contextmanager
    def transaction(self):
        """
        Context manager for atomic write transactions.

        Uses write lock for exclusive access during the transaction.
        Uses IMMEDIATE mode to acquire SQLite write lock immediately,
        preventing deadlocks in concurrent scenarios.
        """
        with self._rwlock.write_lock():
            in_transaction = self.conn.in_transaction

            if not in_transaction:
                self._execute_with_retry(lambda: self.conn.execute("BEGIN IMMEDIATE"))

            try:
                yield self.conn
                if not in_transaction:
                    self._execute_with_retry(lambda: self.conn.execute("COMMIT"))
            except Exception:
                if not in_transaction:
                    try:
                        self.conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass  # Ignore rollback errors (connection may be dead)
                raise

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute write SQL with parameters (with retry logic)."""
        with self._rwlock.write_lock():
            return self._execute_with_retry(lambda: self.conn.execute(sql, params))

    def executemany(self, sql: str, params_list: list) -> sqlite3.Cursor:
        """Execute SQL for multiple parameter sets (with retry logic)."""
        with self._rwlock.write_lock():
            return self._execute_with_retry(lambda: self.conn.executemany(sql, params_list))

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """Execute read query and fetch single row (concurrent reads allowed)."""
        with self._rwlock.read_lock():
            return self._execute_with_retry(lambda: self.conn.execute(sql, params).fetchone())

    def fetchall(self, sql: str, params: tuple = ()) -> list:
        """Execute read query and fetch all rows (concurrent reads allowed)."""
        with self._rwlock.read_lock():
            return self._execute_with_retry(lambda: self.conn.execute(sql, params).fetchall())

    def has_keys(self) -> bool:
        """Check if encryption keys are stored."""
        row = self.fetchone("SELECT 1 FROM keys WHERE id = 1")
        return row is not None

    def get_stored_scrypt_n(self) -> Optional[int]:
        """
        Get stored scrypt_n parameter without loading keys.
        
        Used for pre-auth check to determine if vault needs KDF upgrade.
        Returns None if no vault exists or scrypt_n not stored.
        """
        row = self.fetchone("SELECT scrypt_n FROM keys WHERE id = 1")
        if row:
            return row["scrypt_n"]
        return None

    def store_keys(self, salt: bytes, encrypted_dek: bytes, scrypt_n: int = None) -> None:
        """Store or update encryption keys with KDF parameters."""
        self.execute("""
            INSERT INTO keys (id, salt, encrypted_dek, scrypt_n)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                encrypted_dek = excluded.encrypted_dek,
                scrypt_n = excluded.scrypt_n,
                updated_at = datetime('now')
        """, (salt, encrypted_dek, scrypt_n))

    def load_keys(self) -> Optional[tuple]:
        """Load stored encryption keys and KDF parameters."""
        row = self.fetchone("SELECT salt, encrypted_dek, scrypt_n FROM keys WHERE id = 1")
        if row:
            return row["salt"], row["encrypted_dek"], row["scrypt_n"]
        return None
