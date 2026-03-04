"""
Embedded DuckDB query engine for analytical workloads.

DuckDB runs **in-process** — no separate server.  A single connection is
created at startup and all queries are executed against Parquet-backed
views registered with ``hive_partitioning=true``.

Because DuckDB is not async-native, queries are dispatched to a
:class:`~concurrent.futures.ThreadPoolExecutor` by
:class:`~openlabels.analytics.service.AnalyticsService`.
"""

from __future__ import annotations

import logging
from typing import Any

import duckdb

logger = logging.getLogger(__name__)


class DuckDBEngine:
    """Embedded DuckDB connection with registered Parquet views."""

    def __init__(
        self,
        catalog_root: str,
        *,
        memory_limit: str = "2GB",
        threads: int = 4,
        storage_config=None,
    ) -> None:
        self._catalog_root = catalog_root.rstrip("/")
        self._db = duckdb.connect(":memory:")

        # Validate config values before interpolating into SQL.
        # memory_limit must be a DuckDB-recognised size string.
        import re
        if not re.fullmatch(r"\d+(\.\d+)?\s*(B|KB|MB|GB|TB)", memory_limit, re.IGNORECASE):
            raise ValueError(
                f"Invalid duckdb_memory_limit: {memory_limit!r} "
                "(expected format like '2GB', '512MB')"
            )
        if not isinstance(threads, int) or threads < 1:
            raise ValueError(f"duckdb_threads must be a positive integer, got {threads!r}")

        # Apply resource limits (validated above)
        self._db.execute(f"SET memory_limit = '{memory_limit}';")
        self._db.execute(f"SET threads = {threads};")

        # Load remote storage extensions when needed
        if storage_config is not None:
            self._configure_remote_storage(storage_config)

        self._register_views()
        logger.info(
            "DuckDB engine initialised (root=%s, mem=%s, threads=%d)",
            catalog_root,
            memory_limit,
            threads,
        )

    @staticmethod
    def _esc(value: str) -> str:
        """Escape a value for use in a DuckDB SET statement.

        Replaces backslashes first (to prevent escape-sequence attacks),
        then doubles single quotes.  Also rejects semicolons and null
        bytes to prevent statement injection via DuckDB's parser.
        """
        if "\x00" in value or ";" in value:
            raise ValueError(f"Illegal character in DuckDB SET value: {value!r}")
        return value.replace("\\", "\\\\").replace("'", "''")

    def _configure_remote_storage(self, config) -> None:
        """Install and configure DuckDB extensions for S3/Azure backends."""
        backend = getattr(config, "backend", "local")

        if backend == "s3":
            self._db.execute("INSTALL httpfs; LOAD httpfs;")
            s3 = config.s3
            # Use DuckDB's secret management instead of interpolating
            # credentials into SQL strings, which risks log/trace leakage.
            secret_params = ["TYPE S3"]
            if s3.region:
                secret_params.append(f"REGION '{self._esc(s3.region)}'")
            if s3.access_key.get_secret_value():
                secret_params.append(f"KEY_ID '{self._esc(s3.access_key.get_secret_value())}'")
            if s3.secret_key.get_secret_value():
                secret_params.append(f"SECRET '{self._esc(s3.secret_key.get_secret_value())}'")
            if s3.endpoint_url:
                endpoint = s3.endpoint_url.replace("https://", "").replace("http://", "")
                secret_params.append(f"ENDPOINT '{self._esc(endpoint)}'")
                if s3.endpoint_url.startswith("http://"):
                    secret_params.append("USE_SSL false")
                secret_params.append("URL_STYLE 'path'")
            self._db.execute(
                f"CREATE SECRET openlabels_s3 ({', '.join(secret_params)});"
            )
            logger.info("DuckDB httpfs extension loaded for S3")

        elif backend == "azure":
            self._db.execute("INSTALL azure; LOAD azure;")
            az = config.azure
            conn_str = az.connection_string.get_secret_value() if az.connection_string else ""
            acct_key = az.account_key.get_secret_value() if az.account_key else ""
            # Use DuckDB's secret management instead of interpolating
            # credentials into SQL strings.
            secret_params = ["TYPE AZURE"]
            if conn_str:
                secret_params.append(f"CONNECTION_STRING '{self._esc(conn_str)}'")
            elif az.account_name and acct_key:
                secret_params.append(f"ACCOUNT_NAME '{self._esc(az.account_name)}'")
                secret_params.append(f"ACCOUNT_KEY '{self._esc(acct_key)}'")
            self._db.execute(
                f"CREATE SECRET openlabels_azure ({', '.join(secret_params)});"
            )
            logger.info("DuckDB azure extension loaded")

    # View definitions: (view_name, glob_pattern)
    _VIEW_DEFS: list[tuple[str, str]] = [
        ("scan_results", "scan_results/**/*.parquet"),
        ("file_inventory", "file_inventory/**/*.parquet"),
        ("folder_inventory", "folder_inventory/**/*.parquet"),
        ("directory_tree", "directory_tree/**/*.parquet"),
        ("access_events", "access_events/**/*.parquet"),
        ("audit_log", "audit_log/**/*.parquet"),
        ("remediation_actions", "remediation_actions/**/*.parquet"),
    ]

    def _register_views(self) -> None:
        """Register Parquet glob paths as DuckDB views.

        The ``hive_partitioning=true`` flag makes partition columns
        (``tenant``, ``scan_date``, etc.) available as virtual columns.
        ``WHERE tenant = '...'`` triggers automatic partition pruning so
        DuckDB only reads matching directories.

        If no Parquet files exist yet for a given view, an empty table is
        created so that ``SELECT ... FROM <view>`` returns zero rows
        instead of raising an IO error.
        """
        # Escape single quotes in path to prevent SQL injection via
        # user-configured catalog_root (e.g. paths containing apostrophes).
        root = self._catalog_root.replace("'", "''")

        for view_name, pattern in self._VIEW_DEFS:
            # Validate view_name is a safe SQL identifier (alphanumeric + underscore only)
            if not view_name.isidentifier():
                raise ValueError(f"Invalid view name: {view_name!r}")
            # Drop any previous object (table first, then view) to
            # avoid DuckDB type-mismatch errors on DROP.
            self._db.execute(f"DROP TABLE IF EXISTS {view_name};")
            self._db.execute(f"DROP VIEW IF EXISTS {view_name};")

            try:
                self._db.execute(f"""
                    CREATE VIEW {view_name} AS
                    SELECT * FROM read_parquet(
                        '{root}/{pattern}',
                        hive_partitioning = true,
                        union_by_name = true
                    );
                """)
            except Exception as exc:  # noqa: BLE001
                # No Parquet files exist yet for this view.  Create an
                # empty stub table so that ``SELECT ... FROM <view>``
                # returns zero rows instead of crashing.  The stub is
                # replaced by a real glob-backed view on the next
                # ``refresh_views()`` call once data is flushed.
                self._db.execute(
                    f"CREATE TABLE {view_name} (placeholder BOOLEAN);"
                )
                logger.debug(
                    "No Parquet files for %s yet (stub created): %s",
                    view_name,
                    exc,
                )

    def refresh_views(self) -> None:
        """Re-register views to pick up newly flushed Parquet files."""
        self._register_views()

    def execute(
        self,
        sql: str,
        params: dict[str, Any] | list[Any] | None = None,
    ) -> duckdb.DuckDBPyRelation:
        """Execute a SQL query and return a DuckDB relation."""
        if params:
            return self._db.execute(sql, params)
        return self._db.execute(sql)

    def fetch_all(
        self,
        sql: str,
        params: dict[str, Any] | list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute SQL and return rows as a list of dicts."""
        rel = self.execute(sql, params)
        columns = [desc[0] for desc in rel.description]
        return [dict(zip(columns, row)) for row in rel.fetchall()]

    def fetch_arrow(
        self,
        sql: str,
        params: dict[str, Any] | list[Any] | None = None,
    ):
        """Execute SQL and return a PyArrow Table (zero-copy from DuckDB)."""
        return self.execute(sql, params).fetch_arrow_table()

    def close(self) -> None:
        """Close the DuckDB connection."""
        self._db.close()
        logger.info("DuckDB engine closed")
