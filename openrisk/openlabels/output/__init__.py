"""
OpenLabels Output Module.

Provides label transport functionality:
- Embedded labels: Write/read labels to/from native file metadata
- Virtual labels: Write/read label pointers to/from extended attributes
- Index: Store and resolve virtual labels

Usage:
    >>> from openlabels.output import read_label, write_label, LabelIndex
    >>>
    >>> # Read a label from any file
    >>> result = read_label("document.pdf")
    >>> if result.label_set:
    ...     print(f"Found {len(result.label_set.labels)} labels")
    >>>
    >>> # Write a label (auto-selects transport)
    >>> success, transport = write_label("data.csv", label_set)
    >>> print(f"Wrote {transport} label")
"""

# Unified reader (primary interface)
from .reader import (
    read_label,
    write_label,
    has_label,
    verify_label,
    get_label_transport,
    rescan_if_stale,
    read_labels_batch,
    find_unlabeled,
    find_stale_labels,
    LabelReadResult,
    read_cloud_label_full,
)

# Embedded label operations
from .embed import (
    supports_embedded_labels,
    read_embedded_label,
    write_embedded_label,
)

# Virtual label operations
from .virtual import (
    read_virtual_label,
    write_virtual_label,
    remove_virtual_label,
    has_virtual_label,
    write_cloud_label,
    read_cloud_label,
)

# Index operations
from .index import (
    LabelIndex,
    get_default_index,
    store_label,
    get_label,
    resolve_pointer,
    DEFAULT_INDEX_PATH,
)

# PostgreSQL index (server mode)
from .postgres_index import PostgresLabelIndex


def create_index(
    connection_string: str = None,
    tenant_id: str = "default",
    **kwargs,
):
    """
    Factory function to create a label index.

    Automatically selects SQLite or PostgreSQL based on connection string.

    Args:
        connection_string: Database connection string.
            - None or file path: Uses SQLite (default: ~/.openlabels/index.db)
            - postgresql:// or postgres://: Uses PostgreSQL
        tenant_id: Tenant identifier for multi-tenant isolation
        **kwargs: Additional arguments passed to the index constructor

    Returns:
        LabelIndex (SQLite) or PostgresLabelIndex (PostgreSQL)

    Examples:
        # SQLite (default)
        >>> index = create_index()

        # SQLite with custom path
        >>> index = create_index("/path/to/index.db")

        # PostgreSQL
        >>> index = create_index("postgresql://user:pass@localhost/openlabels")
    """
    if connection_string and connection_string.startswith(('postgresql://', 'postgres://')):
        return PostgresLabelIndex(connection_string, tenant_id=tenant_id, **kwargs)
    else:
        # SQLite
        db_path = connection_string if connection_string else None
        return LabelIndex(db_path=db_path, tenant_id=tenant_id)

# Report generation
from .report import (
    ReportGenerator,
    ReportSummary,
    results_to_json,
    results_to_csv,
    results_to_html,
    results_to_markdown,
    generate_report,
)

__all__ = [
    # Unified interface
    'read_label',
    'write_label',
    'has_label',
    'verify_label',
    'get_label_transport',
    'rescan_if_stale',
    'read_labels_batch',
    'find_unlabeled',
    'find_stale_labels',
    'LabelReadResult',
    'read_cloud_label_full',

    # Embedded
    'supports_embedded_labels',
    'read_embedded_label',
    'write_embedded_label',

    # Virtual
    'read_virtual_label',
    'write_virtual_label',
    'remove_virtual_label',
    'has_virtual_label',
    'write_cloud_label',
    'read_cloud_label',

    # Index
    'LabelIndex',
    'PostgresLabelIndex',
    'create_index',
    'get_default_index',
    'store_label',
    'get_label',
    'resolve_pointer',
    'DEFAULT_INDEX_PATH',

    # Reports
    'ReportGenerator',
    'ReportSummary',
    'results_to_json',
    'results_to_csv',
    'results_to_html',
    'results_to_markdown',
    'generate_report',
]
