"""
Cursor-based pagination utilities for large datasets.

Cursor-based pagination is more efficient than offset-based pagination for large
datasets because it uses WHERE clauses instead of OFFSET. With OFFSET 10000,
the database still has to scan 10,000 rows before returning results. With
cursor-based pagination using indexed columns, the database can jump directly
to the correct position in the index.

Usage:
    # In a route handler:
    cursor_params = CursorPaginationParams(cursor=cursor, limit=limit)
    decoded = cursor_params.decode()  # Returns CursorData or None

    # Build query with cursor
    if decoded:
        query = query.where(
            (Model.created_at, Model.id) < (decoded.timestamp, decoded.id)
        )

    # After fetching results, encode next cursor
    if items:
        next_cursor = encode_cursor(items[-1].id, items[-1].created_at)
"""

import base64
import json
import logging
from datetime import datetime
from typing import Any, Generic, Optional, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CursorData(BaseModel):
    """Decoded cursor data containing pagination position."""

    id: UUID
    timestamp: datetime

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v),
        }


class CursorPaginationParams(BaseModel):
    """Parameters for cursor-based pagination."""

    cursor: Optional[str] = Field(None, description="Pagination cursor from previous response")
    limit: int = Field(50, ge=1, le=100, description="Number of items per page")
    include_total: bool = Field(True, description="Whether to include total count")

    def decode(self) -> Optional[CursorData]:
        """Decode the cursor string into CursorData."""
        if not self.cursor:
            return None
        return decode_cursor(self.cursor)


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response with cursor-based navigation."""

    items: list[T]
    next_cursor: Optional[str] = Field(
        None,
        description="Cursor for fetching next page. None if no more items."
    )
    has_more: bool = Field(
        False,
        description="Whether there are more items after this page"
    )

    class Config:
        from_attributes = True


class CursorPaginatedResponse(BaseModel, Generic[T]):
    """
    Cursor-paginated response model.

    This is the same as PaginatedResponse but with a more explicit name.
    Use this when you need to distinguish from offset-based pagination.
    """

    items: list[T]
    next_cursor: Optional[str] = None
    has_more: bool = False

    class Config:
        from_attributes = True


def encode_cursor(id: UUID, timestamp: datetime) -> str:
    """
    Encode pagination position into a cursor string.

    The cursor is a base64-encoded JSON object containing the ID and timestamp
    of the last item in the current page. This allows efficient keyset pagination
    using: WHERE (timestamp, id) < (cursor_timestamp, cursor_id)

    Args:
        id: UUID of the last item in the current page
        timestamp: Timestamp of the last item (usually created_at or scanned_at)

    Returns:
        Base64-encoded cursor string
    """
    cursor_data = {
        "id": str(id),
        "ts": timestamp.isoformat(),
    }
    json_str = json.dumps(cursor_data, separators=(",", ":"))
    return base64.urlsafe_b64encode(json_str.encode()).decode()


def decode_cursor(cursor: str) -> Optional[CursorData]:
    """
    Decode a cursor string back into pagination position data.

    Args:
        cursor: Base64-encoded cursor string from encode_cursor()

    Returns:
        CursorData with id and timestamp, or None if cursor is invalid

    Raises:
        None - invalid cursors return None instead of raising exceptions
    """
    if not cursor:
        return None

    try:
        # Decode base64
        json_str = base64.urlsafe_b64decode(cursor.encode()).decode()
        data = json.loads(json_str)

        # Parse ID
        id_str = data.get("id")
        if not id_str:
            logger.warning("Cursor missing 'id' field")
            return None

        # Parse timestamp
        ts_str = data.get("ts")
        if not ts_str:
            logger.warning("Cursor missing 'ts' field")
            return None

        return CursorData(
            id=UUID(id_str),
            timestamp=datetime.fromisoformat(ts_str),
        )

    except (ValueError, json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Failed to decode cursor: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error decoding cursor: {e}")
        return None


def build_cursor_condition(
    cursor_data: CursorData,
    timestamp_column: Any,
    id_column: Any,
    descending: bool = True,
) -> Any:
    """
    Build a SQLAlchemy condition for cursor-based pagination.

    For descending order (newest first):
        WHERE (timestamp, id) < (cursor_timestamp, cursor_id)

    For ascending order (oldest first):
        WHERE (timestamp, id) > (cursor_timestamp, cursor_id)

    This uses tuple comparison which is supported by PostgreSQL and most databases.
    The database can use a composite index on (timestamp, id) for efficient seeks.

    Args:
        cursor_data: Decoded cursor containing position
        timestamp_column: SQLAlchemy column for timestamp (e.g., Model.created_at)
        id_column: SQLAlchemy column for ID (e.g., Model.id)
        descending: If True, paginate from newest to oldest

    Returns:
        SQLAlchemy condition for WHERE clause
    """
    from sqlalchemy import tuple_

    cursor_tuple = tuple_(timestamp_column, id_column)
    position_tuple = (cursor_data.timestamp, cursor_data.id)

    if descending:
        return cursor_tuple < position_tuple
    else:
        return cursor_tuple > position_tuple


class CursorInfo:
    """Internal state passed between apply_cursor_pagination and build_cursor_response."""

    def __init__(self, limit: int, sort_column: Any, sort_desc: bool):
        self.limit = limit
        self.sort_column = sort_column
        self.sort_desc = sort_desc


class CursorResponseMeta:
    """Pagination metadata returned by build_cursor_response."""

    def __init__(self, has_more: bool, cursor: Optional[str]):
        self.has_more = has_more
        self.cursor = cursor


def apply_cursor_pagination(
    query: Any,
    model: Any,
    pagination_params: CursorPaginationParams,
    sort_column: Any,
    sort_desc: bool = True,
) -> tuple[Any, CursorInfo]:
    """
    Apply cursor-based pagination to a SQLAlchemy query.

    Decodes the cursor, adds WHERE/ORDER BY/LIMIT clauses, and returns
    a CursorInfo object for use with build_cursor_response.

    Fetches limit+1 rows so build_cursor_response can determine has_more.

    Args:
        query: SQLAlchemy select query
        model: SQLAlchemy model class (must have .id column)
        pagination_params: Cursor pagination parameters
        sort_column: Column to sort/paginate by (e.g., Model.scanned_at)
        sort_desc: Sort descending (newest first) if True

    Returns:
        Tuple of (modified_query, cursor_info)
    """
    from sqlalchemy import desc as sa_desc, asc as sa_asc

    limit = pagination_params.limit
    cursor_data = pagination_params.decode()

    # Apply cursor WHERE clause if cursor was provided
    if cursor_data:
        condition = build_cursor_condition(
            cursor_data,
            timestamp_column=sort_column,
            id_column=model.id,
            descending=sort_desc,
        )
        query = query.where(condition)

    # Apply ORDER BY
    if sort_desc:
        query = query.order_by(sa_desc(sort_column), sa_desc(model.id))
    else:
        query = query.order_by(sa_asc(sort_column), sa_asc(model.id))

    # Fetch one extra row to detect has_more
    query = query.limit(limit + 1)

    cursor_info = CursorInfo(limit=limit, sort_column=sort_column, sort_desc=sort_desc)
    return query, cursor_info


def build_cursor_response(
    result_rows: list,
    cursor_info: CursorInfo,
) -> CursorResponseMeta:
    """
    Build cursor pagination response metadata from query results.

    Checks if there are more results beyond the requested limit and
    generates the next cursor from the last item within the limit.

    Args:
        result_rows: Rows returned by the query (may include one extra)
        cursor_info: CursorInfo from apply_cursor_pagination

    Returns:
        CursorResponseMeta with has_more and cursor fields
    """
    limit = cursor_info.limit
    has_more = len(result_rows) > limit

    if has_more and len(result_rows) >= limit:
        # Use the last item within the limit as the cursor position
        last_item = result_rows[limit - 1]
        sort_col_name = cursor_info.sort_column.key
        timestamp_val = getattr(last_item, sort_col_name)
        next_cursor = encode_cursor(last_item.id, timestamp_val)
    else:
        next_cursor = None

    return CursorResponseMeta(has_more=has_more, cursor=next_cursor)
