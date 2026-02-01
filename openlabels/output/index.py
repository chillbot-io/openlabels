"""
OpenLabels Label Index.

SQLite-based index for storing and resolving virtual labels.

The index stores the full LabelSet data for files using virtual labels
(xattr pointers). It supports:
- Storage and retrieval by labelID
- Version tracking via content_hash
- Querying by entity type, risk score, etc.

Per the spec, the index MUST NOT leave the user's tenant.

Provides structured exception types and optional error propagation
via raise_on_error parameter for distinguishing "not found" from "database error".
"""

import json
import sqlite3
import logging
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from contextlib import contextmanager

from ..core.labels import LabelSet, VirtualLabelPointer
from ..adapters.scanner.constants import DEFAULT_QUERY_LIMIT, DEFAULT_BATCH_SIZE, DATABASE_LOCK_TIMEOUT
from ..core.exceptions import (
    DatabaseError,
    CorruptedDataError,
    NotFoundError,
)

logger = logging.getLogger(__name__)

# Default limit for get_versions() to prevent unbounded memory usage
DEFAULT_VERSION_LIMIT = 100


def _build_filter_clause(
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    risk_tier: Optional[str] = None,
    entity_type: Optional[str] = None,
    since: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> tuple:
    """
    Build WHERE clause and params for label queries.

    Returns:
        Tuple of (where_clause_suffix, params_list)
    """
    clauses = []
    params: List[Any] = []

    if tenant_id is not None:
        clauses.append("o.tenant_id = ?")
        params.append(tenant_id)

    if min_score is not None:
        clauses.append("v.risk_score >= ?")
        params.append(min_score)

    if max_score is not None:
        clauses.append("v.risk_score <= ?")
        params.append(max_score)

    if risk_tier:
        clauses.append("v.risk_tier = ?")
        params.append(risk_tier)

    if entity_type:
        clauses.append("v.entity_types LIKE ?")
        params.append(f"%{entity_type}%")

    if since:
        clauses.append("v.scanned_at >= ?")
        params.append(since)

    where_suffix = " AND ".join(clauses) if clauses else "1=1"
    return where_suffix, params


def _validate_label_json(json_str: str) -> dict:
    """
    Validate and parse label JSON data.

    Uses compact field names per OpenLabels spec:
    - v: version
    - id: label_id
    - hash: content_hash
    - labels: array of {t, c, d, h, n?, x?}
    - src: source
    - ts: timestamp

    Args:
        json_str: JSON string from database

    Returns:
        Parsed and validated dict

    Raises:
        CorruptedDataError: If JSON is malformed or fails schema validation
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise CorruptedDataError(f"Malformed JSON in database: {e}")

    # Basic schema validation (without external dependency)
    if not isinstance(data, dict):
        raise CorruptedDataError("Label data must be an object")

    # Validate required fields (compact schema)
    required_fields = ["v", "id", "hash", "labels", "src", "ts"]
    for field in required_fields:
        if field not in data:
            raise CorruptedDataError(f"Missing required field: {field}")

    if not isinstance(data.get("v"), int):
        raise CorruptedDataError("v (version) must be an integer")

    if not isinstance(data.get("id"), str) or not data["id"]:
        raise CorruptedDataError("id (label_id) must be a non-empty string")

    if not isinstance(data.get("hash"), str) or not data["hash"]:
        raise CorruptedDataError("hash (content_hash) must be a non-empty string")

    if not isinstance(data.get("labels"), list):
        raise CorruptedDataError("labels must be an array")

    if not isinstance(data.get("src"), str):
        raise CorruptedDataError("src (source) must be a string")

    if not isinstance(data.get("ts"), int):
        raise CorruptedDataError("ts (timestamp) must be an integer")

    # Validate each label entry (compact schema: t, c, d, h)
    for i, label in enumerate(data["labels"]):
        if not isinstance(label, dict):
            raise CorruptedDataError(f"labels[{i}] must be an object")
        if "t" not in label or not isinstance(label.get("t"), str):
            raise CorruptedDataError(f"labels[{i}].t (type) must be a string")
        if "c" not in label:
            raise CorruptedDataError(f"labels[{i}].c (confidence) is required")
        conf = label.get("c")
        if not isinstance(conf, (int, float)) or conf < 0 or conf > 1:
            raise CorruptedDataError(
                f"labels[{i}].c (confidence) must be a number between 0 and 1"
            )
        if "d" not in label or not isinstance(label.get("d"), str):
            raise CorruptedDataError(f"labels[{i}].d (detector) must be a string")
        if "h" not in label or not isinstance(label.get("h"), str):
            raise CorruptedDataError(f"labels[{i}].h (value_hash) must be a string")
        if "n" in label and not isinstance(label.get("n"), int):
            raise CorruptedDataError(f"labels[{i}].n (count) must be an integer")

    return data

# Default index location
DEFAULT_INDEX_PATH = Path.home() / ".openlabels" / "index.db"


class LabelIndex:
    """
    SQLite-based label index for virtual label resolution.

    The index stores:
    - label_objects: Core identity (labelID, tenant, created_at)
    - label_versions: Version history (content_hash, labels, risk_score)

    Features thread-local connection pooling for efficient reuse of SQLite
    connections within the same thread, reducing connection overhead.

    Usage:
        >>> index = LabelIndex()
        >>> index.store(label_set)
        >>> retrieved = index.get(label_id, content_hash)
        >>> index.close()  # Optional: explicitly close connections
    """

    SCHEMA_VERSION = 1

    # Thread-local storage for connection pooling
    # Each thread gets its own connection to avoid SQLite threading issues
    _thread_local = threading.local()

    def __init__(
        self,
        db_path: Optional[str] = None,
        tenant_id: str = "default",
    ):
        """
        Initialize the label index.

        Args:
            db_path: Path to SQLite database. If None, uses default location.
            tenant_id: Tenant identifier for multi-tenant isolation.
        """
        self.db_path = Path(db_path) if db_path else DEFAULT_INDEX_PATH
        self.tenant_id = tenant_id
        self._lock = threading.Lock()
        self._closed = False

        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript("""
                -- Schema version tracking
                CREATE TABLE IF NOT EXISTS schema_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                -- Core label identity (immutable once created)
                CREATE TABLE IF NOT EXISTS label_objects (
                    label_id    TEXT PRIMARY KEY,
                    tenant_id   TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    file_path   TEXT,
                    file_name   TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_label_objects_tenant
                    ON label_objects(tenant_id);

                -- Version history (append-only, one row per content_hash)
                CREATE TABLE IF NOT EXISTS label_versions (
                    label_id      TEXT NOT NULL,
                    content_hash  TEXT NOT NULL,
                    scanned_at    TEXT NOT NULL,
                    labels_json   TEXT NOT NULL,
                    source        TEXT NOT NULL,
                    risk_score    INTEGER,
                    risk_tier     TEXT,
                    entity_types  TEXT,
                    PRIMARY KEY (label_id, content_hash),
                    FOREIGN KEY (label_id) REFERENCES label_objects(label_id)
                );
                CREATE INDEX IF NOT EXISTS idx_label_versions_hash
                    ON label_versions(content_hash);
                CREATE INDEX IF NOT EXISTS idx_label_versions_score
                    ON label_versions(risk_score);
                CREATE INDEX IF NOT EXISTS idx_label_versions_scanned
                    ON label_versions(scanned_at);

                -- File path mapping for quick lookup
                CREATE TABLE IF NOT EXISTS file_mappings (
                    file_path     TEXT PRIMARY KEY,
                    label_id      TEXT NOT NULL,
                    content_hash  TEXT NOT NULL,
                    updated_at    TEXT NOT NULL,
                    FOREIGN KEY (label_id) REFERENCES label_objects(label_id)
                );
                CREATE INDEX IF NOT EXISTS idx_file_mappings_label
                    ON file_mappings(label_id);
            """)

            # Set schema version
            conn.execute(
                "INSERT OR REPLACE INTO schema_info (key, value) VALUES (?, ?)",
                ("schema_version", str(self.SCHEMA_VERSION)),
            )
            conn.commit()

    def _get_thread_connection(self) -> sqlite3.Connection:
        """
        Get or create a thread-local database connection.

        Uses thread-local storage to reuse connections within the same thread,
        reducing connection overhead. Each thread gets its own connection to
        avoid SQLite threading issues.

        Returns:
            sqlite3.Connection for the current thread
        """
        # Use db_path as key to support multiple LabelIndex instances
        conn_key = f"conn_{self.db_path}"

        conn = getattr(self._thread_local, conn_key, None)

        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,  # We handle thread safety via thread-local
                timeout=DATABASE_LOCK_TIMEOUT,
            )
            conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrent access
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            setattr(self._thread_local, conn_key, conn)
            logger.debug(f"Created new connection for thread {threading.current_thread().name}")

        return conn

    def _validate_connection(self, conn: sqlite3.Connection) -> bool:
        """
        Validate that a connection is still usable.

        Connections can become stale due to:
        - Database file being deleted/moved
        - Disk errors
        - WAL corruption
        - Long idle periods (some environments)

        Args:
            conn: SQLite connection to validate

        Returns:
            True if connection is healthy, False otherwise
        """
        try:
            # Simple query to verify connection works
            conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def _invalidate_connection(self, conn_key: str, conn: sqlite3.Connection) -> None:
        """Close and remove an invalid connection."""
        try:
            conn.close()
        except sqlite3.Error as e:
            logger.warning(f"Error closing stale database connection: {e}")
        try:
            delattr(self._thread_local, conn_key)
        except AttributeError:
            logger.debug(f"Connection key {conn_key} already removed from thread-local storage")

    @contextmanager
    def _get_connection(self):
        """
        Get database connection with context management and health checks.

        Uses thread-local connection pooling for efficiency.
        Connection is NOT closed after use - it's reused for subsequent operations.
        Validates connection health and recreates if stale.
        """
        if self._closed:
            raise DatabaseError("LabelIndex has been closed")

        conn_key = f"conn_{self.db_path}"
        conn = self._get_thread_connection()

        # Validate connection health - recreate if stale
        if not self._validate_connection(conn):
            logger.warning(
                f"Stale database connection detected for thread "
                f"{threading.current_thread().name}, reconnecting"
            )
            self._invalidate_connection(conn_key, conn)
            conn = self._get_thread_connection()

        try:
            yield conn
        except sqlite3.Error as e:
            # On database error, invalidate connection so next call gets fresh one
            self._invalidate_connection(conn_key, conn)
            raise DatabaseError(f"Database error: {e}") from e

    def close(self):
        """
        Close all thread-local connections.

        Should be called when the LabelIndex is no longer needed to release
        database resources. Safe to call multiple times.
        """
        with self._lock:
            self._closed = True

        # Close connection for current thread
        conn_key = f"conn_{self.db_path}"
        conn = getattr(self._thread_local, conn_key, None)
        if conn is not None:
            try:
                conn.close()
                logger.debug(f"Closed connection for thread {threading.current_thread().name}")
            except sqlite3.Error as e:
                logger.warning(f"Error closing connection: {e}")
            try:
                delattr(self._thread_local, conn_key)
            except AttributeError:
                logger.debug(f"Connection key {conn_key} already removed during close()")

    def __del__(self):
        """Cleanup on garbage collection."""
        try:
            self.close()
        except Exception as e:
            # Can't reliably use logger in __del__ (may be garbage collected)
            # Print to stderr so cleanup failures are visible
            import sys
            print(f"LabelIndex cleanup warning: {e}", file=sys.stderr)

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - closes connections."""
        self.close()
        return False

    @contextmanager
    def _transaction(self, conn):
        """
        Execute operations within an explicit transaction.

        Uses BEGIN IMMEDIATE to acquire write lock upfront, preventing
        deadlocks in multi-writer scenarios. Automatically rolls back
        on exception and commits on success.

        Args:
            conn: SQLite connection

        Yields:
            The connection for executing statements

        Raises:
            DatabaseError: If transaction fails
        """
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            try:
                conn.rollback()
            except sqlite3.Error as rollback_err:
                # Log rollback failure - important for debugging connection issues
                logger.warning(f"Transaction rollback also failed: {rollback_err}")
            raise DatabaseError(f"Transaction failed: {e}") from e
        except Exception:
            try:
                conn.rollback()
            except sqlite3.Error as rollback_err:
                logger.warning(f"Transaction rollback failed: {rollback_err}")
            raise

    def store(
        self,
        label_set: LabelSet,
        file_path: Optional[str] = None,
        risk_score: Optional[int] = None,
        risk_tier: Optional[str] = None,
    ) -> bool:
        """
        Store a LabelSet in the index.

        Creates or updates the label object and adds a new version record.

        Args:
            label_set: The LabelSet to store
            file_path: Optional file path for mapping
            risk_score: Optional computed risk score
            risk_tier: Optional risk tier (MINIMAL, LOW, MEDIUM, HIGH, CRITICAL)

        Returns:
            True if successful, False otherwise
        """
        now = datetime.utcnow().isoformat()
        entity_types = ','.join(sorted(set(l.type for l in label_set.labels)))

        try:
            with self._get_connection() as conn:
                with self._transaction(conn):
                    # Upsert label object
                    conn.execute("""
                        INSERT INTO label_objects (label_id, tenant_id, created_at, file_path, file_name)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(label_id) DO UPDATE SET
                            file_path = COALESCE(excluded.file_path, file_path),
                            file_name = COALESCE(excluded.file_name, file_name)
                    """, (
                        label_set.label_id,
                        self.tenant_id,
                        now,
                        file_path,
                        Path(file_path).name if file_path else None,
                    ))

                    # Insert version (or update if same content_hash)
                    conn.execute("""
                        INSERT INTO label_versions
                            (label_id, content_hash, scanned_at, labels_json, source,
                             risk_score, risk_tier, entity_types)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(label_id, content_hash) DO UPDATE SET
                            scanned_at = excluded.scanned_at,
                            labels_json = excluded.labels_json,
                            source = excluded.source,
                            risk_score = COALESCE(excluded.risk_score, risk_score),
                            risk_tier = COALESCE(excluded.risk_tier, risk_tier),
                            entity_types = excluded.entity_types
                    """, (
                        label_set.label_id,
                        label_set.content_hash,
                        now,
                        label_set.to_json(compact=True),
                        label_set.source,
                        risk_score,
                        risk_tier,
                        entity_types,
                    ))

                    # Update file mapping if path provided
                    if file_path:
                        conn.execute("""
                            INSERT INTO file_mappings (file_path, label_id, content_hash, updated_at)
                            VALUES (?, ?, ?, ?)
                            ON CONFLICT(file_path) DO UPDATE SET
                                label_id = excluded.label_id,
                                content_hash = excluded.content_hash,
                                updated_at = excluded.updated_at
                        """, (
                            file_path,
                            label_set.label_id,
                            label_set.content_hash,
                            now,
                        ))

                return True

        except DatabaseError as e:
            logger.error(f"Failed to store label: {e}")
            return False
        except sqlite3.Error as e:
            logger.error(f"Failed to store label: {e}")
            return False

    def get(
        self,
        label_id: str,
        content_hash: Optional[str] = None,
        raise_on_error: bool = False,
    ) -> Optional[LabelSet]:
        """
        Retrieve a LabelSet from the index.

        Args:
            label_id: The label ID to look up
            content_hash: Optional specific version. If None, returns latest.
            raise_on_error: If True, raise exceptions instead of returning None.
                           Allows callers to distinguish "not found" from
                           "database error" .

        Returns:
            LabelSet if found, None otherwise (when raise_on_error=False)

        Raises:
            NotFoundError: Label not found (when raise_on_error=True)
            DatabaseError: Database operation failed (when raise_on_error=True)
            CorruptedDataError: Stored data is corrupted (when raise_on_error=True)
        """
        try:
            with self._get_connection() as conn:
                if content_hash:
                    # Get specific version
                    row = conn.execute("""
                        SELECT labels_json FROM label_versions
                        WHERE label_id = ? AND content_hash = ?
                    """, (label_id, content_hash)).fetchone()
                else:
                    # Get latest version
                    row = conn.execute("""
                        SELECT labels_json FROM label_versions
                        WHERE label_id = ?
                        ORDER BY scanned_at DESC
                        LIMIT 1
                    """, (label_id,)).fetchone()

                if row:
                    # Validate JSON before deserializing
                    validated_data = _validate_label_json(row['labels_json'])
                    return LabelSet.from_dict(validated_data)

                # Not found
                if raise_on_error:
                    raise NotFoundError(
                        f"Label not found: {label_id}",
                        resource_type="label",
                        resource_id=label_id,
                    )
                return None

        except CorruptedDataError as e:
            logger.error(f"Corrupted label data for {label_id}: {e}")
            if raise_on_error:
                raise
            return None
        except sqlite3.Error as e:
            logger.error(f"Failed to get label: {e}")
            if raise_on_error:
                raise DatabaseError(f"Failed to get label: {e}", operation="get") from e
            return None

    def get_by_path(
        self,
        file_path: str,
        raise_on_error: bool = False,
    ) -> Optional[LabelSet]:
        """
        Retrieve a LabelSet by file path.

        Args:
            file_path: The file path to look up
            raise_on_error: If True, raise exceptions instead of returning None
                           .

        Returns:
            LabelSet if found, None otherwise (when raise_on_error=False)

        Raises:
            NotFoundError: Label not found for path (when raise_on_error=True)
            DatabaseError: Database operation failed (when raise_on_error=True)
            CorruptedDataError: Stored data is corrupted (when raise_on_error=True)
        """
        try:
            with self._get_connection() as conn:
                row = conn.execute("""
                    SELECT v.labels_json
                    FROM file_mappings m
                    JOIN label_versions v ON m.label_id = v.label_id
                        AND m.content_hash = v.content_hash
                    WHERE m.file_path = ?
                """, (file_path,)).fetchone()

                if row:
                    # Validate JSON before deserializing
                    validated_data = _validate_label_json(row['labels_json'])
                    return LabelSet.from_dict(validated_data)

                # Not found
                if raise_on_error:
                    raise NotFoundError(
                        f"No label found for path: {file_path}",
                        resource_type="file_label",
                        resource_id=file_path,
                    )
                return None

        except CorruptedDataError as e:
            logger.error(f"Corrupted label data for path {file_path}: {e}")
            if raise_on_error:
                raise
            return None
        except sqlite3.Error as e:
            logger.error(f"Failed to get label by path: {e}")
            if raise_on_error:
                raise DatabaseError(f"Failed to get label by path: {e}", operation="get_by_path") from e
            return None

    def resolve(self, pointer: VirtualLabelPointer) -> Optional[LabelSet]:
        """
        Resolve a virtual label pointer to a full LabelSet.

        Args:
            pointer: VirtualLabelPointer from xattr

        Returns:
            LabelSet if found, None otherwise
        """
        return self.get(pointer.label_id, pointer.content_hash)

    def get_versions(
        self,
        label_id: str,
        limit: int = DEFAULT_VERSION_LIMIT,
    ) -> List[Dict[str, Any]]:
        """
        Get versions of a label.

        Args:
            label_id: The label ID
            limit: Maximum versions to return (default: 100)

        Returns:
            List of version metadata dicts, most recent first
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT content_hash, scanned_at, source, risk_score, risk_tier, entity_types
                    FROM label_versions
                    WHERE label_id = ?
                    ORDER BY scanned_at DESC
                    LIMIT ?
                """, (label_id, limit))

                return [dict(row) for row in cursor]

        except sqlite3.Error as e:
            logger.error(f"Failed to get versions: {e}")
            return []

    def query(
        self,
        min_score: Optional[int] = None,
        max_score: Optional[int] = None,
        risk_tier: Optional[str] = None,
        entity_type: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = DEFAULT_QUERY_LIMIT,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Query the index for labels matching criteria.

        Args:
            min_score: Minimum risk score
            max_score: Maximum risk score
            risk_tier: Risk tier filter
            entity_type: Entity type filter (e.g., "SSN")
            since: ISO timestamp for scanned_at filter
            limit: Maximum results per page (default: 100)
            offset: Number of results to skip for pagination (default: 0)

        Returns:
            List of matching label metadata
        """
        # Validate pagination params
        limit = max(1, min(limit, 10000))  # Cap at 10k per page
        offset = max(0, offset)

        where_clause, params = _build_filter_clause(
            min_score=min_score,
            max_score=max_score,
            risk_tier=risk_tier,
            entity_type=entity_type,
            since=since,
        )

        query = f"""
            SELECT
                o.label_id,
                o.file_path,
                o.file_name,
                v.content_hash,
                v.scanned_at,
                v.risk_score,
                v.risk_tier,
                v.entity_types
            FROM label_objects o
            JOIN label_versions v ON o.label_id = v.label_id
            WHERE {where_clause}
            ORDER BY v.scanned_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        try:
            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                return [dict(row) for row in cursor]

        except sqlite3.Error as e:
            logger.error(f"Query failed: {e}")
            return []

    def query_count(
        self,
        min_score: Optional[int] = None,
        max_score: Optional[int] = None,
        risk_tier: Optional[str] = None,
        entity_type: Optional[str] = None,
        since: Optional[str] = None,
    ) -> int:
        """
        Count labels matching criteria (for pagination).

        Args:
            min_score: Minimum risk score
            max_score: Maximum risk score
            risk_tier: Risk tier filter
            entity_type: Entity type filter (e.g., "SSN")
            since: ISO timestamp for scanned_at filter

        Returns:
            Total count of matching labels
        """
        where_clause, params = _build_filter_clause(
            min_score=min_score,
            max_score=max_score,
            risk_tier=risk_tier,
            entity_type=entity_type,
            since=since,
        )

        query = f"""
            SELECT COUNT(*)
            FROM label_objects o
            JOIN label_versions v ON o.label_id = v.label_id
            WHERE {where_clause}
        """

        try:
            with self._get_connection() as conn:
                result = conn.execute(query, params).fetchone()
                return result[0] if result else 0

        except sqlite3.Error as e:
            logger.error(f"Query count failed: {e}")
            return 0

    def delete(self, label_id: str) -> bool:
        """
        Delete a label and all its versions.

        Args:
            label_id: The label ID to delete

        Returns:
            True if deleted, False otherwise
        """
        try:
            with self._get_connection() as conn:
                with self._transaction(conn):
                    conn.execute(
                        "DELETE FROM file_mappings WHERE label_id = ?",
                        (label_id,),
                    )
                    conn.execute(
                        "DELETE FROM label_versions WHERE label_id = ?",
                        (label_id,),
                    )
                    conn.execute(
                        "DELETE FROM label_objects WHERE label_id = ?",
                        (label_id,),
                    )
                return True

        except DatabaseError as e:
            logger.error(f"Delete failed: {e}")
            return False
        except sqlite3.Error as e:
            logger.error(f"Delete failed: {e}")
            return False

    def count(self) -> Dict[str, int]:
        """Get counts of labels and versions."""
        try:
            with self._get_connection() as conn:
                labels = conn.execute(
                    "SELECT COUNT(*) FROM label_objects WHERE tenant_id = ?",
                    (self.tenant_id,),
                ).fetchone()[0]

                versions = conn.execute(
                    """SELECT COUNT(*) FROM label_versions v
                       JOIN label_objects o ON v.label_id = o.label_id
                       WHERE o.tenant_id = ?""",
                    (self.tenant_id,),
                ).fetchone()[0]

                return {"labels": labels, "versions": versions}

        except sqlite3.Error as e:
            logger.error(f"Count failed: {e}")
            return {"labels": 0, "versions": 0}

    def export(
        self,
        output_path: str,
        batch_size: int = DEFAULT_BATCH_SIZE,
        min_score: Optional[int] = None,
        max_score: Optional[int] = None,
        risk_tier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Export labels to a JSONL file.

        Args:
            output_path: Path to output file
            batch_size: Number of records to process per batch (default: 1000)
            min_score: Optional minimum risk score filter
            max_score: Optional maximum risk score filter
            risk_tier: Optional risk tier filter

        Returns:
            Dict with export stats: {"success": bool, "count": int, "error": str|None}
        """
        count = 0
        try:
            with self._get_connection() as conn:
                where_clause, params = _build_filter_clause(
                    min_score=min_score,
                    max_score=max_score,
                    risk_tier=risk_tier,
                    tenant_id=self.tenant_id,
                )

                query = f"""
                    SELECT v.labels_json, v.risk_score, v.risk_tier, o.file_path
                    FROM label_versions v
                    JOIN label_objects o ON v.label_id = o.label_id
                    WHERE {where_clause}
                    ORDER BY v.scanned_at DESC
                """

                cursor = conn.execute(query, params)

                with open(output_path, 'w') as f:
                    batch = []
                    for row in cursor:
                        record = json.loads(row['labels_json'])
                        record['_risk_score'] = row['risk_score']
                        record['_risk_tier'] = row['risk_tier']
                        record['_file_path'] = row['file_path']
                        batch.append(json.dumps(record))
                        count += 1

                        if len(batch) >= batch_size:
                            f.write('\n'.join(batch) + '\n')
                            batch.clear()

                    if batch:
                        f.write('\n'.join(batch) + '\n')

                return {"success": True, "count": count, "error": None}

        except (sqlite3.Error, OSError) as e:
            logger.error(f"Export failed: {e}")
            return {"success": False, "count": count, "error": str(e)}

    def export_iter(
        self,
        min_score: Optional[int] = None,
        max_score: Optional[int] = None,
        risk_tier: Optional[str] = None,
    ):
        """
        Iterator for streaming export of labels.

        Yields one record at a time for memory-efficient processing.

        Args:
            min_score: Optional minimum risk score filter
            max_score: Optional maximum risk score filter
            risk_tier: Optional risk tier filter

        Yields:
            Dict containing label data with _risk_score, _risk_tier, _file_path
        """
        try:
            with self._get_connection() as conn:
                where_clause, params = _build_filter_clause(
                    min_score=min_score,
                    max_score=max_score,
                    risk_tier=risk_tier,
                    tenant_id=self.tenant_id,
                )

                query = f"""
                    SELECT v.labels_json, v.risk_score, v.risk_tier, o.file_path
                    FROM label_versions v
                    JOIN label_objects o ON v.label_id = o.label_id
                    WHERE {where_clause}
                    ORDER BY v.scanned_at DESC
                """

                cursor = conn.execute(query, params)

                for row in cursor:
                    record = json.loads(row['labels_json'])
                    record['_risk_score'] = row['risk_score']
                    record['_risk_tier'] = row['risk_tier']
                    record['_file_path'] = row['file_path']
                    yield record

        except sqlite3.Error as e:
            logger.error(f"Export iteration failed: {e}")
            return



# --- Convenience Functions ---


import warnings

_default_index: Optional[LabelIndex] = None
_default_index_lock = threading.Lock()
_default_index_warning_issued = False


def get_default_index(warn: bool = True) -> LabelIndex:
    """
    Get the default label index singleton (thread-safe).

    WARNING: Default index shares state across all callers .
    For isolated operation, create explicit LabelIndex instances.

    Args:
        warn: If True, emit a warning about shared state (default True).
              Set to False to suppress warning (e.g., in internal code).

    Returns:
        The default shared LabelIndex instance
    """
    global _default_index, _default_index_warning_issued

    with _default_index_lock:
        # Warn about shared state (once per process)
        # NOTE: Both warning check AND creation must be inside same lock
        # to prevent race conditions
        if warn and not _default_index_warning_issued:
            warnings.warn(
                "Using default index shares state across all callers. "
                "For isolated operation, create explicit LabelIndex instances. "
                "Suppress this warning with get_default_index(warn=False).",
                UserWarning,
                stacklevel=2,
            )
            _default_index_warning_issued = True

        if _default_index is None:
            _default_index = LabelIndex()
        return _default_index


def reset_default_index() -> None:
    """Reset the default index (mainly for testing)."""
    global _default_index, _default_index_warning_issued
    with _default_index_lock:
        _default_index = None
        _default_index_warning_issued = False


def store_label(
    label_set: LabelSet,
    file_path: Optional[str] = None,
    risk_score: Optional[int] = None,
    risk_tier: Optional[str] = None,
) -> bool:
    """Store a label in the default index."""
    return get_default_index().store(label_set, file_path, risk_score, risk_tier)


def get_label(
    label_id: str,
    content_hash: Optional[str] = None,
) -> Optional[LabelSet]:
    """Get a label from the default index."""
    return get_default_index().get(label_id, content_hash)


def resolve_pointer(pointer: VirtualLabelPointer) -> Optional[LabelSet]:
    """Resolve a virtual label pointer using the default index."""
    return get_default_index().resolve(pointer)
