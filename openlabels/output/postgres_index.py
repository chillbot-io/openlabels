"""
PostgreSQL-based Label Index for server mode deployments.

Provides the same interface as LabelIndex (SQLite) but backed by PostgreSQL
for multi-tenant server deployments with concurrent access.

Requires: psycopg[binary] or psycopg2-binary

Connection string format:
    postgresql://user:password@host:port/database
    postgres://user:password@host:port/database

Usage:
    >>> from openlabels.output.postgres_index import PostgresLabelIndex
    >>> index = PostgresLabelIndex("postgresql://user:pass@localhost/openlabels")
    >>> index.store(label_set)
    >>> label = index.get(label_id)
"""

import json
import logging
import os
import threading
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from ..core.labels import LabelSet, VirtualLabelPointer
from ..adapters.scanner.constants import DEFAULT_QUERY_LIMIT
from ..core.exceptions import (
    DatabaseError,
    CorruptedDataError,
    NotFoundError,
)

logger = logging.getLogger(__name__)

# Default version limit for get_versions()
DEFAULT_VERSION_LIMIT = 100


def _escape_like_pattern(value: str) -> str:
    """
    Escape special characters in SQL LIKE patterns to prevent injection.

    The characters % and _ have special meaning in LIKE patterns:
    - % matches any sequence of characters
    - _ matches any single character

    This function escapes them so they match literally.
    """
    # Escape backslash first (it's the escape character), then % and _
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def _validate_label_json(json_str: str) -> dict:
    """Validate and parse label JSON data."""
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise CorruptedDataError(f"Malformed JSON in database: {e}")

    if not isinstance(data, dict):
        raise CorruptedDataError("Label data must be an object")

    required_fields = ["labelID", "content_hash", "labels", "source"]
    for field in required_fields:
        if field not in data:
            raise CorruptedDataError(f"Missing required field: {field}")

    return data


def _get_psycopg():
    """Import psycopg, trying psycopg3 first, then psycopg2."""
    try:
        import psycopg
        return psycopg, 3
    except ImportError:
        pass

    try:
        import psycopg2
        return psycopg2, 2
    except ImportError:
        raise ImportError(
            "PostgreSQL support requires psycopg or psycopg2. "
            "Install with: pip install 'psycopg[binary]' or pip install psycopg2-binary"
        )


class PostgresLabelIndex:
    """
    PostgreSQL-based label index for server mode deployments.

    Provides the same interface as LabelIndex (SQLite) but uses PostgreSQL
    for better concurrent access and multi-tenant server deployments.

    Features:
    - Connection pooling via thread-local connections
    - UPSERT operations for atomic updates
    - Multi-tenant isolation via tenant_id
    - Same query interface as SQLite version

    Usage:
        >>> index = PostgresLabelIndex("postgresql://localhost/openlabels")
        >>> index.store(label_set, file_path="/path/to/file")
        >>> label = index.get(label_id)
    """

    SCHEMA_VERSION = 1

    # Thread-local storage for connections, keyed by connection string hash
    _thread_local = threading.local()

    def __init__(
        self,
        connection_string: str,
        tenant_id: str = "default",
    ):
        """
        Initialize PostgreSQL label index.

        Args:
            connection_string: PostgreSQL connection URL
                (e.g., postgresql://user:pass@host:5432/dbname)
            tenant_id: Tenant identifier for multi-tenant isolation
        """
        self.connection_string = connection_string
        self.tenant_id = tenant_id
        self._lock = threading.Lock()
        self._closed = False
        # Unique key for this connection in thread-local storage
        self._conn_key = f"conn_{hash(connection_string)}"

        # Import psycopg
        self._psycopg, self._psycopg_version = _get_psycopg()

        # Initialize schema
        self._init_db()

    def _get_connection(self):
        """Get or create thread-local database connection."""
        if self._closed:
            raise DatabaseError("PostgresLabelIndex has been closed")

        conn = getattr(self._thread_local, self._conn_key, None)

        if conn is None or (hasattr(conn, 'closed') and conn.closed):
            conn = self._psycopg.connect(self.connection_string)
            setattr(self._thread_local, self._conn_key, conn)
            logger.debug(f"Created new PostgreSQL connection for thread {threading.current_thread().name}")

        return conn

    @contextmanager
    def _connection(self):
        """Connection context manager with error handling."""
        conn = self._get_connection()
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Database error: {e}") from e

    @contextmanager
    def _cursor(self):
        """Cursor context manager with automatic commit/rollback.

        Exception handling is delegated to _connection() for consistency.
        All database errors are wrapped in DatabaseError by _connection().
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            try:
                yield cursor
                conn.commit()
            finally:
                cursor.close()

    def _init_db(self):
        """Initialize database schema."""
        with self._cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS label_objects (
                    label_id    TEXT PRIMARY KEY,
                    tenant_id   TEXT NOT NULL,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    file_path   TEXT,
                    file_name   TEXT
                )
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_label_objects_tenant
                    ON label_objects(tenant_id)
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS label_versions (
                    label_id      TEXT NOT NULL,
                    content_hash  TEXT NOT NULL,
                    scanned_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    labels_json   JSONB NOT NULL,
                    source        TEXT NOT NULL,
                    risk_score    INTEGER,
                    risk_tier     TEXT,
                    entity_types  TEXT,
                    PRIMARY KEY (label_id, content_hash),
                    FOREIGN KEY (label_id) REFERENCES label_objects(label_id)
                        ON DELETE CASCADE
                )
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_label_versions_hash
                    ON label_versions(content_hash)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_label_versions_score
                    ON label_versions(risk_score)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_label_versions_scanned
                    ON label_versions(scanned_at)
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS file_mappings (
                    file_path     TEXT PRIMARY KEY,
                    label_id      TEXT NOT NULL,
                    content_hash  TEXT NOT NULL,
                    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (label_id) REFERENCES label_objects(label_id)
                        ON DELETE CASCADE
                )
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_file_mappings_label
                    ON file_mappings(label_id)
            """)

            # Store schema version
            cur.execute("""
                INSERT INTO schema_info (key, value)
                VALUES ('schema_version', %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """, (str(self.SCHEMA_VERSION),))

        logger.info("PostgreSQL schema initialized")

    def close(self):
        """Close the database connection."""
        with self._lock:
            self._closed = True

        conn = getattr(self._thread_local, self._conn_key, None)
        if conn is not None:
            try:
                conn.close()
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")
            try:
                delattr(self._thread_local, self._conn_key)
            except AttributeError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def store(
        self,
        label_set: LabelSet,
        file_path: Optional[str] = None,
        risk_score: Optional[int] = None,
        risk_tier: Optional[str] = None,
    ) -> bool:
        """
        Store a LabelSet in the index.

        Args:
            label_set: The LabelSet to store
            file_path: Optional file path for mapping
            risk_score: Optional computed risk score
            risk_tier: Optional risk tier

        Returns:
            True if successful
        """
        entity_types = ','.join(sorted(set(l.type for l in label_set.labels)))
        file_name = os.path.basename(file_path) if file_path else None

        try:
            with self._cursor() as cur:
                # Upsert label object
                cur.execute("""
                    INSERT INTO label_objects (label_id, tenant_id, file_path, file_name)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (label_id) DO UPDATE SET
                        file_path = COALESCE(EXCLUDED.file_path, label_objects.file_path),
                        file_name = COALESCE(EXCLUDED.file_name, label_objects.file_name)
                """, (
                    label_set.label_id,
                    self.tenant_id,
                    file_path,
                    file_name,
                ))

                # Insert/update version
                cur.execute("""
                    INSERT INTO label_versions
                        (label_id, content_hash, labels_json, source,
                         risk_score, risk_tier, entity_types)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (label_id, content_hash) DO UPDATE SET
                        scanned_at = NOW(),
                        labels_json = EXCLUDED.labels_json,
                        source = EXCLUDED.source,
                        risk_score = COALESCE(EXCLUDED.risk_score, label_versions.risk_score),
                        risk_tier = COALESCE(EXCLUDED.risk_tier, label_versions.risk_tier),
                        entity_types = EXCLUDED.entity_types
                """, (
                    label_set.label_id,
                    label_set.content_hash,
                    label_set.to_json(compact=True),
                    label_set.source,
                    risk_score,
                    risk_tier,
                    entity_types,
                ))

                # Update file mapping if path provided
                if file_path:
                    cur.execute("""
                        INSERT INTO file_mappings (file_path, label_id, content_hash)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (file_path) DO UPDATE SET
                            label_id = EXCLUDED.label_id,
                            content_hash = EXCLUDED.content_hash,
                            updated_at = NOW()
                    """, (file_path, label_set.label_id, label_set.content_hash))

            return True

        except Exception as e:
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
            raise_on_error: If True, raise exceptions instead of returning None

        Returns:
            LabelSet if found, None otherwise
        """
        try:
            with self._cursor() as cur:
                if content_hash:
                    cur.execute("""
                        SELECT labels_json FROM label_versions
                        WHERE label_id = %s AND content_hash = %s
                    """, (label_id, content_hash))
                else:
                    cur.execute("""
                        SELECT labels_json FROM label_versions
                        WHERE label_id = %s
                        ORDER BY scanned_at DESC
                        LIMIT 1
                    """, (label_id,))

                row = cur.fetchone()

                if row:
                    json_str = row[0] if isinstance(row[0], str) else json.dumps(row[0])
                    validated_data = _validate_label_json(json_str)
                    return LabelSet.from_dict(validated_data)

                if raise_on_error:
                    raise NotFoundError(
                        f"Label not found: {label_id}",
                        resource_type="label",
                        resource_id=label_id,
                    )
                return None

        except CorruptedDataError:
            if raise_on_error:
                raise
            return None
        except Exception as e:
            logger.error(f"Failed to get label: {e}")
            if raise_on_error:
                raise DatabaseError(f"Failed to get label: {e}") from e
            return None

    def get_by_path(
        self,
        file_path: str,
        raise_on_error: bool = False,
    ) -> Optional[LabelSet]:
        """Retrieve a LabelSet by file path."""
        try:
            with self._cursor() as cur:
                cur.execute("""
                    SELECT v.labels_json
                    FROM file_mappings m
                    JOIN label_versions v ON m.label_id = v.label_id
                        AND m.content_hash = v.content_hash
                    WHERE m.file_path = %s
                """, (file_path,))

                row = cur.fetchone()

                if row:
                    json_str = row[0] if isinstance(row[0], str) else json.dumps(row[0])
                    validated_data = _validate_label_json(json_str)
                    return LabelSet.from_dict(validated_data)

                if raise_on_error:
                    raise NotFoundError(
                        f"No label found for path: {file_path}",
                        resource_type="file_label",
                        resource_id=file_path,
                    )
                return None

        except CorruptedDataError:
            if raise_on_error:
                raise
            return None
        except Exception as e:
            logger.error(f"Failed to get label by path: {e}")
            if raise_on_error:
                raise DatabaseError(f"Failed to get label by path: {e}") from e
            return None

    def resolve(self, pointer: VirtualLabelPointer) -> Optional[LabelSet]:
        """Resolve a virtual label pointer to a full LabelSet."""
        return self.get(pointer.label_id, pointer.content_hash)

    def get_versions(
        self,
        label_id: str,
        limit: int = DEFAULT_VERSION_LIMIT,
    ) -> List[Dict[str, Any]]:
        """Get version history for a label."""
        try:
            with self._cursor() as cur:
                cur.execute("""
                    SELECT content_hash, scanned_at, source, risk_score, risk_tier, entity_types
                    FROM label_versions
                    WHERE label_id = %s
                    ORDER BY scanned_at DESC
                    LIMIT %s
                """, (label_id, limit))

                columns = ['content_hash', 'scanned_at', 'source', 'risk_score', 'risk_tier', 'entity_types']
                # Use iterator instead of fetchall() to avoid memory exhaustion
                results = []
                for row in cur:
                    results.append(dict(zip(columns, row)))
                return results

        except Exception as e:
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
        """Query the index for labels matching criteria."""
        limit = max(1, min(limit, 10000))
        offset = max(0, offset)

        conditions = ["o.tenant_id = %s"]
        params: List[Any] = [self.tenant_id]

        if min_score is not None:
            conditions.append("v.risk_score >= %s")
            params.append(min_score)

        if max_score is not None:
            conditions.append("v.risk_score <= %s")
            params.append(max_score)

        if risk_tier:
            conditions.append("v.risk_tier = %s")
            params.append(risk_tier)

        if entity_type:
            # Escape LIKE wildcards to prevent pattern injection
            escaped_type = _escape_like_pattern(entity_type)
            conditions.append("v.entity_types LIKE %s ESCAPE '\\'")
            params.append(f"%{escaped_type}%")

        if since:
            conditions.append("v.scanned_at >= %s")
            params.append(since)

        # SECURITY: Build query using explicit string joining instead of f-string
        # interpolation. The where_clause is safe because it's constructed only
        # from hardcoded condition strings above - never from user input.
        # All user-provided values go through parameterized query placeholders.
        where_clause = " AND ".join(conditions)
        params.extend([limit, offset])

        query_parts = [
            "SELECT",
            "    o.label_id,",
            "    o.file_path,",
            "    o.file_name,",
            "    v.content_hash,",
            "    v.scanned_at,",
            "    v.risk_score,",
            "    v.risk_tier,",
            "    v.entity_types",
            "FROM label_objects o",
            "JOIN label_versions v ON o.label_id = v.label_id",
            "WHERE " + where_clause,
            "ORDER BY v.scanned_at DESC",
            "LIMIT %s OFFSET %s",
        ]
        query = "\n".join(query_parts)

        try:
            with self._cursor() as cur:
                cur.execute(query, params)

                columns = ['label_id', 'file_path', 'file_name', 'content_hash',
                          'scanned_at', 'risk_score', 'risk_tier', 'entity_types']
                # Use iterator instead of fetchall() to avoid memory exhaustion
                results = []
                for row in cur:
                    results.append(dict(zip(columns, row)))
                return results

        except Exception as e:
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
        """Count labels matching criteria."""
        conditions = ["o.tenant_id = %s"]
        params: List[Any] = [self.tenant_id]

        if min_score is not None:
            conditions.append("v.risk_score >= %s")
            params.append(min_score)

        if max_score is not None:
            conditions.append("v.risk_score <= %s")
            params.append(max_score)

        if risk_tier:
            conditions.append("v.risk_tier = %s")
            params.append(risk_tier)

        if entity_type:
            # Escape LIKE wildcards to prevent pattern injection
            escaped_type = _escape_like_pattern(entity_type)
            conditions.append("v.entity_types LIKE %s ESCAPE '\\'")
            params.append(f"%{escaped_type}%")

        if since:
            conditions.append("v.scanned_at >= %s")
            params.append(since)

        # SECURITY: Build query using explicit string joining (see query() for rationale)
        where_clause = " AND ".join(conditions)

        query_parts = [
            "SELECT COUNT(*)",
            "FROM label_objects o",
            "JOIN label_versions v ON o.label_id = v.label_id",
            "WHERE " + where_clause,
        ]
        query = "\n".join(query_parts)

        try:
            with self._cursor() as cur:
                cur.execute(query, params)

                result = cur.fetchone()
                return result[0] if result else 0

        except Exception as e:
            logger.error(f"Query count failed: {e}")
            return 0

    def delete(self, label_id: str) -> bool:
        """Delete a label and all its versions."""
        try:
            with self._cursor() as cur:
                # CASCADE will handle versions and mappings
                cur.execute(
                    "DELETE FROM label_objects WHERE label_id = %s",
                    (label_id,),
                )
            return True

        except Exception as e:
            logger.error(f"Delete failed: {e}")
            return False

    def count(self) -> Dict[str, int]:
        """Get counts of labels and versions."""
        try:
            with self._cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM label_objects WHERE tenant_id = %s",
                    (self.tenant_id,),
                )
                result = cur.fetchone()
                labels = result[0] if result else 0

                cur.execute("""
                    SELECT COUNT(*) FROM label_versions v
                    JOIN label_objects o ON v.label_id = o.label_id
                    WHERE o.tenant_id = %s
                """, (self.tenant_id,))
                result = cur.fetchone()
                versions = result[0] if result else 0

                return {"labels": labels, "versions": versions}

        except Exception as e:
            logger.error(f"Count failed: {e}")
            return {"labels": 0, "versions": 0}


def create_index(
    connection_string: Optional[str] = None,
    tenant_id: str = "default",
) -> "PostgresLabelIndex":
    """
    Factory function to create a PostgreSQL label index.

    Args:
        connection_string: PostgreSQL connection URL
        tenant_id: Tenant identifier

    Returns:
        PostgresLabelIndex instance

    Raises:
        ValueError: If connection_string is not provided
        ImportError: If psycopg is not installed
    """
    if not connection_string:
        raise ValueError(
            "PostgreSQL connection string required. "
            "Format: postgresql://user:password@host:port/database"
        )

    return PostgresLabelIndex(connection_string, tenant_id)
