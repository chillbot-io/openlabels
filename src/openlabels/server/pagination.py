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

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field

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

    cursor: str | None = Field(None, description="Pagination cursor from previous response")
    limit: int = Field(50, ge=1, le=100, description="Number of items per page")
    include_total: bool = Field(True, description="Whether to include total count")

    def decode(self) -> CursorData | None:
        """Decode the cursor string into CursorData."""
        if not self.cursor:
            return None
        return decode_cursor(self.cursor)


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response with cursor-based navigation."""

    items: list[T]
    next_cursor: str | None = Field(
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
    next_cursor: str | None = None
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


def decode_cursor(cursor: str) -> CursorData | None:
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
    except (TypeError, UnicodeDecodeError, AttributeError) as e:
        logger.error(f"Unexpected error decoding cursor: {e}")
        return None


async def apply_cursor_pagination(
    session: Any,
    query: Any,
    model_class: Any,
    params: CursorPaginationParams,
    *,
    timestamp_column: Any | None = None,
) -> CursorPaginatedResponse[Any]:
    """Apply cursor-based pagination to a SQLAlchemy query.

    Uses the existing ``(id, timestamp)`` composite cursor format.
    Fetches ``limit + 1`` rows to detect *has_more* without a COUNT query.

    Args:
        session: AsyncSession to execute the query.
        query: SQLAlchemy ``select()`` statement (before ordering/limiting).
        model_class: ORM model with ``.id`` and ``.created_at`` columns.
        params: Decoded cursor and page-size limit.
        timestamp_column: Column to sort on (defaults to ``model_class.created_at``).

    Returns:
        ``CursorPaginatedResponse`` with items, next_cursor, and has_more.
    """
    ts_col = timestamp_column if timestamp_column is not None else model_class.created_at
    id_col = model_class.id

    cursor_data = params.decode()
    if cursor_data:
        # Keyset pagination: WHERE (ts, id) < (cursor_ts, cursor_id)
        query = query.where(
            (ts_col < cursor_data.timestamp)
            | ((ts_col == cursor_data.timestamp) & (id_col < cursor_data.id))
        )

    query = query.order_by(ts_col.desc(), id_col.desc())
    query = query.limit(params.limit + 1)

    result = await session.execute(query)
    items = list(result.scalars().all())

    has_more = len(items) > params.limit
    if has_more:
        items = items[: params.limit]

    next_cursor: str | None = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.id, getattr(last, ts_col.key))

    return CursorPaginatedResponse(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
    )
