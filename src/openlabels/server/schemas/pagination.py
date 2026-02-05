"""
Standardized pagination models and utilities.

Provides:
- Generic PaginatedResponse model for all list endpoints
- PaginationParams for query parameters
- Helper functions to create paginated responses from SQLAlchemy queries
- Cursor-based pagination for large datasets
"""

import base64
import json
from datetime import datetime
from typing import Any, Generic, Optional, Sequence, TypeVar, Union
from uuid import UUID

from fastapi import Query
from pydantic import BaseModel, Field
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession


T = TypeVar("T")


# =============================================================================
# OFFSET-BASED PAGINATION
# =============================================================================


class PaginatedResponse(BaseModel, Generic[T]):
    """
    Generic paginated response model.

    Use this model for all list endpoints to ensure consistent pagination
    across the API.

    Example:
        @router.get("", response_model=PaginatedResponse[UserResponse])
        async def list_users(...) -> PaginatedResponse[UserResponse]:
            ...
    """

    items: list[T]
    total: int = Field(..., description="Total number of items matching the query")
    page: int = Field(..., ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(..., ge=1, description="Number of items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether there is a next page")
    has_previous: bool = Field(..., description="Whether there is a previous page")


class PaginationParams:
    """
    Pagination query parameters with defaults and limits.

    Usage:
        @router.get("")
        async def list_items(
            pagination: PaginationParams = Depends(),
            ...
        ):
            # Use pagination.page, pagination.page_size, pagination.offset
    """

    def __init__(
        self,
        page: int = Query(1, ge=1, le=10000, description="Page number (1-indexed)"),
        page_size: int = Query(
            50, ge=1, le=100, alias="page_size", description="Items per page (max 100)"
        ),
    ):
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        """Calculate offset for SQL query."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Alias for page_size for SQL query."""
        return self.page_size


async def paginate_query(
    session: AsyncSession,
    query: Select,
    pagination: PaginationParams,
    transformer: Optional[callable] = None,
) -> dict[str, Any]:
    """
    Execute a paginated query and return pagination metadata.

    Args:
        session: SQLAlchemy async session
        query: SQLAlchemy Select query (should NOT include offset/limit)
        pagination: PaginationParams instance
        transformer: Optional function to transform each result item

    Returns:
        Dictionary with pagination data ready for PaginatedResponse

    Example:
        query = select(User).where(User.tenant_id == tenant_id).order_by(User.created_at.desc())
        result = await paginate_query(
            session, query, pagination,
            transformer=lambda u: UserResponse.model_validate(u)
        )
        return PaginatedResponse[UserResponse](**result)
    """
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await session.execute(count_query)
    total = count_result.scalar() or 0

    # Calculate pagination metadata
    total_pages = (total + pagination.page_size - 1) // pagination.page_size if total > 0 else 1
    has_next = pagination.page < total_pages
    has_previous = pagination.page > 1

    # Get paginated results
    paginated_query = query.offset(pagination.offset).limit(pagination.limit)
    result = await session.execute(paginated_query)
    items = result.scalars().all()

    # Transform items if transformer provided
    if transformer:
        items = [transformer(item) for item in items]

    return {
        "items": items,
        "total": total,
        "page": pagination.page,
        "page_size": pagination.page_size,
        "total_pages": total_pages,
        "has_next": has_next,
        "has_previous": has_previous,
    }


def create_paginated_response(
    items: Sequence[T],
    total: int,
    page: int,
    page_size: int,
) -> dict[str, Any]:
    """
    Create pagination response dict from pre-fetched items.

    Use this when you already have items and total count.

    Args:
        items: List of items for current page
        total: Total count of all items
        page: Current page number (1-indexed)
        page_size: Items per page

    Returns:
        Dictionary ready for PaginatedResponse construction
    """
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    return {
        "items": list(items),
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_previous": page > 1,
    }


# =============================================================================
# CURSOR-BASED PAGINATION
# =============================================================================


class CursorPaginatedResponse(BaseModel, Generic[T]):
    """
    Cursor-based paginated response for large datasets.

    Cursor pagination is more efficient for large datasets because:
    - No OFFSET queries (which get slower as offset increases)
    - Stable pagination even when data changes
    - Better for infinite scroll UIs

    The cursor is an opaque string that encodes the position in the result set.
    """

    items: list[T]
    next_cursor: Optional[str] = Field(
        None, description="Cursor for next page (null if no more results)"
    )
    previous_cursor: Optional[str] = Field(
        None, description="Cursor for previous page (null if at start)"
    )
    has_next: bool = Field(..., description="Whether there are more results")
    has_previous: bool = Field(..., description="Whether there are previous results")
    page_size: int = Field(..., description="Number of items per page")


class CursorPaginationParams:
    """
    Cursor-based pagination query parameters.

    Usage:
        @router.get("")
        async def list_items(
            pagination: CursorPaginationParams = Depends(),
            ...
        ):
            # Use pagination.cursor, pagination.page_size, pagination.direction
    """

    def __init__(
        self,
        cursor: Optional[str] = Query(None, description="Pagination cursor"),
        page_size: int = Query(
            50, ge=1, le=100, alias="page_size", description="Items per page (max 100)"
        ),
        direction: str = Query(
            "forward",
            pattern="^(forward|backward)$",
            description="Pagination direction",
        ),
    ):
        self.cursor = cursor
        self.page_size = page_size
        self.direction = direction

    @property
    def limit(self) -> int:
        """Return limit for query (page_size + 1 to detect has_next)."""
        return self.page_size + 1


def encode_cursor(
    values: dict[str, Any],
    direction: str = "forward",
) -> str:
    """
    Encode cursor values to an opaque string.

    Args:
        values: Dictionary of column values to encode (e.g., {"id": "uuid", "created_at": "2024-01-01T00:00:00"})
        direction: Pagination direction

    Returns:
        Base64 encoded cursor string
    """
    # Convert UUID and datetime to strings for JSON serialization
    serializable = {}
    for key, value in values.items():
        if isinstance(value, UUID):
            serializable[key] = str(value)
        elif isinstance(value, datetime):
            serializable[key] = value.isoformat()
        else:
            serializable[key] = value

    cursor_data = {"v": serializable, "d": direction}
    return base64.urlsafe_b64encode(json.dumps(cursor_data).encode()).decode()


def decode_cursor(cursor: str) -> tuple[dict[str, Any], str]:
    """
    Decode a cursor string to its values.

    Args:
        cursor: Base64 encoded cursor string

    Returns:
        Tuple of (values dict, direction)

    Raises:
        ValueError: If cursor is invalid
    """
    try:
        cursor_data = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        return cursor_data["v"], cursor_data.get("d", "forward")
    except Exception as e:
        raise ValueError(f"Invalid cursor: {e}")


async def cursor_paginate_query(
    session: AsyncSession,
    base_query: Select,
    pagination: CursorPaginationParams,
    cursor_columns: list[tuple[Any, str]],
    transformer: Optional[callable] = None,
) -> dict[str, Any]:
    """
    Execute a cursor-paginated query.

    Args:
        session: SQLAlchemy async session
        base_query: Base SQLAlchemy Select query (without cursor filters)
        pagination: CursorPaginationParams instance
        cursor_columns: List of (column, name) tuples for cursor.
                       First column should be the primary sort column.
                       Example: [(Model.created_at, "created_at"), (Model.id, "id")]
        transformer: Optional function to transform each result item

    Returns:
        Dictionary with cursor pagination data ready for CursorPaginatedResponse

    Example:
        query = select(ScanResult).where(ScanResult.tenant_id == tenant_id)
        result = await cursor_paginate_query(
            session,
            query.order_by(ScanResult.scanned_at.desc(), ScanResult.id.desc()),
            pagination,
            cursor_columns=[(ScanResult.scanned_at, "scanned_at"), (ScanResult.id, "id")],
            transformer=lambda r: ResultResponse.model_validate(r)
        )
        return CursorPaginatedResponse[ResultResponse](**result)
    """
    query = base_query

    # Apply cursor filter if cursor provided
    if pagination.cursor:
        try:
            cursor_values, cursor_direction = decode_cursor(pagination.cursor)
        except ValueError as e:
            # Invalid cursor, start from beginning
            cursor_values = None
            cursor_direction = pagination.direction

        if cursor_values:
            # Build cursor filter
            # For descending order: WHERE (col1, col2) < (val1, val2)
            # For ascending order: WHERE (col1, col2) > (val1, val2)
            if len(cursor_columns) == 1:
                col, name = cursor_columns[0]
                cursor_val = cursor_values.get(name)
                if cursor_val is not None:
                    if pagination.direction == "forward":
                        query = query.where(col < cursor_val)
                    else:
                        query = query.where(col > cursor_val)
            else:
                # Multi-column cursor (e.g., created_at + id for tie-breaking)
                from sqlalchemy import tuple_

                cols = tuple_(*[col for col, _ in cursor_columns])
                vals = tuple(cursor_values.get(name) for _, name in cursor_columns)

                if None not in vals:
                    if pagination.direction == "forward":
                        query = query.where(cols < vals)
                    else:
                        query = query.where(cols > vals)

    # Execute query with limit + 1 to detect has_next
    query = query.limit(pagination.limit)
    result = await session.execute(query)
    items = list(result.scalars().all())

    # Check if there are more results
    has_next = len(items) > pagination.page_size
    if has_next:
        items = items[: pagination.page_size]

    # Build cursors
    next_cursor = None
    previous_cursor = None

    if items:
        # Next cursor from last item
        if has_next:
            last_item = items[-1]
            cursor_vals = {}
            for col, name in cursor_columns:
                cursor_vals[name] = getattr(last_item, name, None)
            next_cursor = encode_cursor(cursor_vals, "forward")

        # Previous cursor from first item (if we used a cursor to get here)
        if pagination.cursor:
            first_item = items[0]
            cursor_vals = {}
            for col, name in cursor_columns:
                cursor_vals[name] = getattr(first_item, name, None)
            previous_cursor = encode_cursor(cursor_vals, "backward")

    # Transform items if transformer provided
    if transformer:
        items = [transformer(item) for item in items]

    return {
        "items": items,
        "next_cursor": next_cursor,
        "previous_cursor": previous_cursor,
        "has_next": has_next,
        "has_previous": pagination.cursor is not None,
        "page_size": pagination.page_size,
    }
