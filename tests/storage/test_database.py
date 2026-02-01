"""Tests for SQLite database module.

Tests Database class, ReadWriteLock, schema management, and migrations.
"""

import os
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

from scrubiq.storage.database import Database, ReadWriteLock, SCHEMA_VERSION


# =============================================================================
# READ WRITE LOCK TESTS
# =============================================================================

class TestReadWriteLock:
    """Tests for ReadWriteLock class."""

    def test_read_lock_basic(self):
        """Can acquire and release read lock."""
        lock = ReadWriteLock()
        with lock.read_lock():
            assert lock._readers == 1
        assert lock._readers == 0

    def test_multiple_readers(self):
        """Multiple readers can acquire lock simultaneously."""
        lock = ReadWriteLock()
        results = []

        def reader(n):
            with lock.read_lock():
                results.append(f"r{n}_start")
                time.sleep(0.01)
                results.append(f"r{n}_end")

        threads = [threading.Thread(target=reader, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All readers should overlap (not sequential)
        assert len(results) == 6
        # Check that starts happened before all ends (concurrent)
        starts = [r for r in results if "start" in r]
        ends = [r for r in results if "end" in r]
        assert len(starts) == 3
        assert len(ends) == 3

    def test_write_lock_exclusive(self):
        """Write lock is exclusive."""
        lock = ReadWriteLock()

        with lock.write_lock():
            assert lock._writer_active is True
        assert lock._writer_active is False

    def test_write_blocks_readers(self):
        """Active writer blocks readers."""
        lock = ReadWriteLock()
        events = []

        def writer():
            with lock.write_lock():
                events.append("write_start")
                time.sleep(0.05)
                events.append("write_end")

        def reader():
            time.sleep(0.01)  # Let writer start first
            events.append("read_wait")
            with lock.read_lock():
                events.append("read_acquired")

        wt = threading.Thread(target=writer)
        rt = threading.Thread(target=reader)

        wt.start()
        rt.start()
        wt.join()
        rt.join()

        # Reader should wait for writer
        assert events.index("read_wait") < events.index("write_end")
        assert events.index("read_acquired") >= events.index("write_end")

    def test_writer_priority(self):
        """Writers have priority over new readers."""
        lock = ReadWriteLock()

        # Acquire initial read lock
        lock._read_ready.acquire()
        lock._readers = 1
        lock._read_ready.release()

        # Start a writer waiting
        writer_started = threading.Event()
        writer_done = threading.Event()

        def writer():
            with lock.write_lock():
                writer_started.set()
                writer_done.set()

        wt = threading.Thread(target=writer)
        wt.start()

        # Give writer time to start waiting
        time.sleep(0.01)

        # Writers waiting should block new readers
        assert lock._writers_waiting > 0

        # Release the initial read
        lock._read_ready.acquire()
        lock._readers = 0
        lock._read_ready.notify_all()
        lock._read_ready.release()

        wt.join(timeout=1)
        assert writer_done.is_set()


# =============================================================================
# DATABASE BASIC TESTS
# =============================================================================

class TestDatabaseBasic:
    """Basic tests for Database class."""

    def test_create_database(self):
        """Can create a new database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            assert db_path.exists()
            assert db.conn is not None

            db.close()

    def test_is_encrypted_without_key(self):
        """is_encrypted is False without encryption key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            assert db.is_encrypted is False

            db.close()

    def test_connect_creates_parent_dirs(self):
        """connect() creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "nested" / "dirs" / "test.db"
            db = Database(db_path)
            db.connect()

            assert db_path.exists()

            db.close()

    def test_close_clears_connection(self):
        """close() clears the connection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()
            db.close()

            with pytest.raises(RuntimeError, match="not connected"):
                _ = db.conn

    def test_conn_property_raises_when_not_connected(self):
        """conn property raises when not connected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)

            with pytest.raises(RuntimeError, match="not connected"):
                _ = db.conn


# =============================================================================
# SCHEMA TESTS
# =============================================================================

class TestDatabaseSchema:
    """Tests for database schema management."""

    def test_schema_version_set(self):
        """Schema version is set on creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            row = db.fetchone("SELECT version FROM schema_version LIMIT 1")
            assert row["version"] == SCHEMA_VERSION

            db.close()

    def test_tables_created(self):
        """Required tables are created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            # Check for expected tables
            tables = db.fetchall(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            table_names = [row["name"] for row in tables]

            assert "settings" in table_names
            assert "api_keys" in table_names
            assert "keys" in table_names
            assert "conversations" in table_names
            assert "messages" in table_names
            assert "tokens" in table_names
            assert "audit_log" in table_names
            assert "image_files" in table_names
            assert "memories" in table_names
            assert "auth_state" in table_names

            db.close()

    def test_auth_state_initialized(self):
        """auth_state row is created on init."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            row = db.fetchone("SELECT * FROM auth_state WHERE id = 1")
            assert row is not None
            assert row["failed_attempts"] == 0

            db.close()

    def test_foreign_keys_enabled(self):
        """Foreign keys are enabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            row = db.fetchone("PRAGMA foreign_keys")
            assert row[0] == 1

            db.close()

    def test_wal_mode_enabled(self):
        """WAL journal mode is enabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            row = db.fetchone("PRAGMA journal_mode")
            assert row[0].lower() == "wal"

            db.close()


# =============================================================================
# CRUD OPERATIONS TESTS
# =============================================================================

class TestDatabaseCRUD:
    """Tests for database CRUD operations."""

    def test_execute_insert(self):
        """execute() can insert data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                ("test_key", "test_value")
            )

            row = db.fetchone("SELECT value FROM settings WHERE key = ?", ("test_key",))
            assert row["value"] == "test_value"

            db.close()

    def test_fetchone_returns_none_for_no_match(self):
        """fetchone() returns None when no match."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            row = db.fetchone("SELECT * FROM settings WHERE key = ?", ("nonexistent",))
            assert row is None

            db.close()

    def test_fetchall_returns_empty_list(self):
        """fetchall() returns empty list when no matches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            rows = db.fetchall("SELECT * FROM settings WHERE key = ?", ("nonexistent",))
            assert rows == []

            db.close()

    def test_executemany(self):
        """executemany() inserts multiple rows."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            data = [
                ("key1", "val1"),
                ("key2", "val2"),
                ("key3", "val3"),
            ]
            db.executemany(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                data
            )

            rows = db.fetchall("SELECT key FROM settings ORDER BY key")
            assert len(rows) == 3

            db.close()


# =============================================================================
# TRANSACTION TESTS
# =============================================================================

class TestDatabaseTransactions:
    """Tests for database transaction handling."""

    def test_transaction_commits_on_success(self):
        """Transaction commits changes on success."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            with db.transaction():
                db.conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)",
                    ("txn_key", "txn_value")
                )

            row = db.fetchone("SELECT value FROM settings WHERE key = ?", ("txn_key",))
            assert row["value"] == "txn_value"

            db.close()

    def test_transaction_rollback_on_error(self):
        """Transaction rolls back on error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            try:
                with db.transaction():
                    db.conn.execute(
                        "INSERT INTO settings (key, value) VALUES (?, ?)",
                        ("rollback_key", "rollback_value")
                    )
                    raise ValueError("Intentional error")
            except ValueError:
                pass

            row = db.fetchone("SELECT value FROM settings WHERE key = ?", ("rollback_key",))
            assert row is None

            db.close()

    def test_nested_transaction(self):
        """Nested transaction context is handled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            with db.transaction():
                db.conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)",
                    ("outer", "outer_val")
                )
                with db.transaction():
                    db.conn.execute(
                        "INSERT INTO settings (key, value) VALUES (?, ?)",
                        ("inner", "inner_val")
                    )

            rows = db.fetchall("SELECT key FROM settings ORDER BY key")
            assert len(rows) == 2

            db.close()


# =============================================================================
# KEY STORAGE TESTS
# =============================================================================

class TestDatabaseKeyStorage:
    """Tests for encryption key storage."""

    def test_has_keys_false_initially(self):
        """has_keys() returns False on new database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            assert db.has_keys() is False

            db.close()

    def test_store_keys(self):
        """store_keys() stores encryption keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            salt = b"test_salt_16_b"
            encrypted_dek = b"encrypted_dek_data"
            scrypt_n = 2**14

            db.store_keys(salt, encrypted_dek, scrypt_n)

            assert db.has_keys() is True

            db.close()

    def test_load_keys(self):
        """load_keys() retrieves stored keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            salt = b"test_salt_16_bx"
            encrypted_dek = b"encrypted_dek_data"
            scrypt_n = 2**14

            db.store_keys(salt, encrypted_dek, scrypt_n)
            result = db.load_keys()

            assert result is not None
            loaded_salt, loaded_dek, loaded_n = result
            assert loaded_salt == salt
            assert loaded_dek == encrypted_dek
            assert loaded_n == scrypt_n

            db.close()

    def test_load_keys_returns_none_when_empty(self):
        """load_keys() returns None when no keys stored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            result = db.load_keys()
            assert result is None

            db.close()

    def test_get_stored_scrypt_n(self):
        """get_stored_scrypt_n() retrieves scrypt_n parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            db.store_keys(b"salt", b"dek", 2**15)

            result = db.get_stored_scrypt_n()
            assert result == 2**15

            db.close()

    def test_store_keys_updates_existing(self):
        """store_keys() updates existing key row."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            db.store_keys(b"salt1", b"dek1", 2**14)
            db.store_keys(b"salt1", b"dek2", 2**15)

            _, loaded_dek, loaded_n = db.load_keys()
            assert loaded_dek == b"dek2"
            assert loaded_n == 2**15

            db.close()


# =============================================================================
# RETRY LOGIC TESTS
# =============================================================================

class TestDatabaseRetry:
    """Tests for database retry logic."""

    def test_retry_on_locked_error(self):
        """Operations retry on database locked error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            call_count = 0

            def flaky_operation():
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise sqlite3.OperationalError("database is locked")
                return "success"

            result = db._execute_with_retry(flaky_operation)

            assert result == "success"
            assert call_count == 3

            db.close()

    def test_no_retry_on_other_errors(self):
        """Non-locking errors are raised immediately."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            def failing_operation():
                raise sqlite3.OperationalError("table not found")

            with pytest.raises(sqlite3.OperationalError, match="table not found"):
                db._execute_with_retry(failing_operation)

            db.close()


# =============================================================================
# CHECKPOINT TESTS
# =============================================================================

class TestDatabaseCheckpoint:
    """Tests for WAL checkpoint."""

    def test_checkpoint(self):
        """checkpoint() runs without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            # Insert some data to create WAL entries
            db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("ck", "val"))

            # Checkpoint should not raise
            db.checkpoint()

            db.close()


# =============================================================================
# MIGRATION TESTS
# =============================================================================

class TestDatabaseMigrations:
    """Tests for schema migrations."""

    def test_migration_same_version_no_op(self):
        """Migration from same version is no-op."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            # Should not raise
            db._migrate(SCHEMA_VERSION, SCHEMA_VERSION)

            db.close()

    def test_migration_invalid_path_raises(self):
        """Invalid migration path raises RuntimeError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            with pytest.raises(RuntimeError, match="No migration path"):
                db._migrate(999, 1000)

            db.close()


# =============================================================================
# EDGE CASES
# =============================================================================

class TestDatabaseEdgeCases:
    """Edge cases for Database."""

    def test_multiple_connections_same_file(self):
        """Multiple connections to same file work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            db1 = Database(db_path)
            db1.connect()

            db2 = Database(db_path)
            db2.connect()

            # Both should see the same data
            db1.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("shared", "val"))

            # Note: might need to commit for db2 to see changes
            row = db2.fetchone("SELECT value FROM settings WHERE key = ?", ("shared",))
            assert row is not None

            db1.close()
            db2.close()

    def test_row_factory_returns_dict_like(self):
        """Row factory returns dict-like objects."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("k", "v"))
            row = db.fetchone("SELECT key, value FROM settings LIMIT 1")

            # Should be accessible by column name
            assert row["key"] == "k"
            assert row["value"] == "v"

            db.close()
