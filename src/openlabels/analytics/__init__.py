"""
OLAP analytics layer for OpenLabels.

Provides columnar analytics via DuckDB + Parquet, offloading heavy
aggregation queries from PostgreSQL. When ``catalog.enabled`` is False
(the default), all analytics still flow through PostgreSQL.

Public API::

    from openlabels.analytics import AnalyticsService, DuckDBEngine
    from openlabels.analytics.storage import create_storage
"""

from openlabels.analytics.engine import DuckDBEngine
from openlabels.analytics.service import AnalyticsService

__all__ = ["AnalyticsService", "DuckDBEngine"]
