"""
Standardized pagination utilities for OpenLabels API.

Provides consistent pagination across all endpoints with support for:
- Cursor-based pagination for large datasets (efficient, no offset penalty)
- Offset-based pagination for backward compatibility
- Standardized response format

Cursor-based pagination is recommended for:
- Large datasets (>10k rows)
- Real-time data that changes frequently
- Mobile/infinite scroll UIs

Usage:
    from openlabels.server.pagination import (
        PaginationParams,
        CursorPaginationParams,
        PaginatedResponse,
        CursorPaginatedResponse,
        encode_cursor,
        decode_cursor,
        apply_cursor_pagination,
    )

    # Cursor-based pagination
    @router.get("/results", response_model=CursorPaginatedResponse[ResultResponse])
    async def list_results(
        pagination: CursorPaginationParams = Depends(),
    ):
        query = select(ScanResult).order_by(ScanResult.scanned_at.desc())
        query, cursor_info = apply_cursor_pagination(query, ScanResult, pagination)
        ...

    # Offset-based pagination
    @router.get("/items", response_model=PaginatedResponse[ItemResponse])
    async def list_items(
        pagination: PaginationParams = Depends(),
    ):
        ...
"""

import base64
import json
import logging
from datetime import datetime
from typing import Any, Generic, Optional, TypeVar, Sequence
from uuid import UUID

from fastapi import Query
from pydantic import BaseModel, Field
from sqlalchemy import Select, desc, asc
from sqlalchemy.orm import InstrumentedAttribute

logger = logging.getLogger(__name__)

T = TypeVar("T")


# =============================================================================
# PAGINATION METADATA SCHEMAS
# =============================================================================


class PaginationMeta(BaseModel):
    """
    Standardized pagination metadata for offset-based pagination.

    Provides consistent field naming across all paginated endpoints.
    """

    total: int = Field(description="Total number of items matching the query")
    page: int = Field(description="Current page number (1-indexed)")
    page_size: int = Field(description="Number of items per page")
    total_pages: int = Field(description="Total number of pages")
    has_more: bool = Field(description="Whether there are more pages after this one")

    @classmethod
    def from_offset(cls, total: int, page: int, page_size: int) -> "PaginationMeta":
        """Create pagination metadata from offset-based parameters."""
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1
        return cls(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_more=page < total_pages,
        )


class CursorPaginationMeta(BaseModel):
    """
    Pagination metadata for cursor-based pagination.

    Cursors are opaque tokens that encode position information.
    """

    cursor: Optional[str] = Field(
        None, description="Cursor for fetching the next page (null if no more pages)"
    )
    has_more: bool = Field(description="Whether there are more items after this cursor")
    total: Optional[int] = Field(
        None,
        description="Total count of items (optional, may be omitted for performance)",
    )


# =============================================================================
# PAGINATED RESPONSE SCHEMAS
# =============================================================================


class PaginatedResponse(BaseModel, Generic[T]):
    """
    Standardized paginated response format for offset-based pagination.

    Example:
        {
            "data": [...],
            "pagination": {
                "total": 1234,
                "page": 1,
                "page_size": 50,
                "total_pages": 25,
                "has_more": true
            }
        }
    """

    data: list[T] = Field(description="List of items for this page")
    pagination: PaginationMeta = Field(description="Pagination metadata")

    class Config:
        # Allow arbitrary types for generic type parameter
        arbitrary_types_allowed = True


class CursorPaginatedResponse(BaseModel, Generic[T]):
    """
    Standardized paginated response format for cursor-based pagination.

    Cursor-based pagination is more efficient for large datasets as it
    doesn't require counting total rows or using OFFSET which degrades
    with large offsets.

    Example:
        {
            "data": [...],
            "pagination": {
                "cursor": "eyJpZCI6IjEyMzQifQ==",
                "has_more": true,
                "total": 1234  // optional
            }
        }
    """

    data: list[T] = Field(description="List of items for this page")
    pagination: CursorPaginationMeta = Field(description="Pagination metadata")

    class Config:
        arbitrary_types_allowed = True


# =============================================================================
# LEGACY RESPONSE SCHEMAS (for backward compatibility)
# =============================================================================


class LegacyPaginatedResponse(BaseModel, Generic[T]):
    """
    Legacy paginated response format for backward compatibility.

    DEPRECATED: Use PaginatedResponse or CursorPaginatedResponse instead.

    This format maintains compatibility with existing API clients.
    New endpoints should use the standardized formats.
    """

    items: list[T] = Field(description="List of items for this page")
    total: int = Field(description="Total number of items")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    total_pages: int = Field(description="Total number of pages")

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_paginated(
        cls, data: Sequence[T], total: int, page: int, page_size: int
    ) -> "LegacyPaginatedResponse[T]":
        """Create legacy response from components."""
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1
        return cls(
            items=list(data),
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )


# =============================================================================
# PAGINATION PARAMETERS (FastAPI Dependencies)
# =============================================================================


class PaginationParams:
    """
    Dependency for offset-based pagination parameters.

    Usage:
        @router.get("/items")
        async def list_items(pagination: PaginationParams = Depends()):
            offset = pagination.offset
            limit = pagination.limit
            ...
    """

    def __init__(
        self,
        page: int = Query(1, ge=1, description="Page number (1-indexed)"),
        page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    ):
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        """Calculate offset from page number."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Alias for page_size for consistency with SQLAlchemy."""
        return self.page_size


class CursorPaginationParams:
    """
    Dependency for cursor-based pagination parameters.

    Supports both forward pagination (using after cursor) and
    backward pagination (using before cursor).

    Usage:
        @router.get("/items")
        async def list_items(pagination: CursorPaginationParams = Depends()):
            if pagination.cursor:
                cursor_data = decode_cursor(pagination.cursor)
                ...
    """

    def __init__(
        self,
        cursor: Optional[str] = Query(
            None,
            description="Cursor from previous response for fetching next page",
        ),
        limit: int = Query(50, ge=1, le=100, description="Number of items to return"),
        include_total: bool = Query(
            False,
            description="Include total count (may impact performance for large datasets)",
        ),
    ):
        self.cursor = cursor
        self.limit = limit
        self.include_total = include_total


# =============================================================================
# CURSOR ENCODING/DECODING
# =============================================================================


class CursorData(BaseModel):
    """
    Data encoded in a pagination cursor.

    The cursor encodes the position of the last item in the current page,
    allowing the next query to efficiently continue from that point.
    """

    # Primary sort key (usually timestamp)
    sort_value: Any = Field(description="Value of the sort column for the last item")
    # Tiebreaker (usually primary key)
    id_value: str = Field(description="ID of the last item (for tiebreaking)")
    # Direction (for bidirectional pagination)
    direction: str = Field(default="forward", description="Pagination direction")

    class Config:
        arbitrary_types_allowed = True


def encode_cursor(
    sort_value: Any,
    id_value: UUID | str,
    direction: str = "forward",
) -> str:
    """
    Encode cursor data into an opaque string token.

    The cursor is base64-encoded JSON to be URL-safe and opaque to clients.
    Clients should treat cursors as opaque tokens and not parse them.

    Args:
        sort_value: Value of the sort column for the last item
        id_value: UUID or string ID of the last item
        direction: "forward" or "backward"

    Returns:
        Base64-encoded cursor string
    """
    # Convert datetime to ISO format for JSON serialization
    if isinstance(sort_value, datetime):
        sort_value = sort_value.isoformat()

    # Convert UUID to string
    if isinstance(id_value, UUID):
        id_value = str(id_value)

    cursor_data = {
        "s": sort_value,  # sort_value (short key for smaller tokens)
        "i": id_value,  # id_value
        "d": direction,  # direction
    }

    json_str = json.dumps(cursor_data, separators=(",", ":"))
    return base64.urlsafe_b64encode(json_str.encode()).decode()


def decode_cursor(cursor: str) -> Optional[CursorData]:
    """
    Decode a cursor string back into cursor data.

    Args:
        cursor: Base64-encoded cursor string

    Returns:
        CursorData if valid, None if invalid/malformed
    """
    try:
        json_str = base64.urlsafe_b64decode(cursor.encode()).decode()
        data = json.loads(json_str)

        return CursorData(
            sort_value=data.get("s"),
            id_value=data.get("i", ""),
            direction=data.get("d", "forward"),
        )
    except Exception as e:
        logger.warning(f"Failed to decode cursor: {e}")
        return None


# =============================================================================
# QUERY HELPERS
# =============================================================================


def apply_cursor_pagination(
    query: Select,
    model: type,
    pagination: CursorPaginationParams,
    sort_column: Optional[InstrumentedAttribute] = None,
    id_column: Optional[InstrumentedAttribute] = None,
    sort_desc: bool = True,
) -> tuple[Select, dict]:
    """
    Apply cursor-based pagination to a SQLAlchemy query.

    Uses the "seek method" (keyset pagination) for efficient pagination
    without the performance penalty of large OFFSETs.

    Args:
        query: SQLAlchemy select query
        model: SQLAlchemy model class
        pagination: CursorPaginationParams from request
        sort_column: Column to sort by (defaults to model.created_at or model.scanned_at)
        id_column: Column for tiebreaking (defaults to model.id)
        sort_desc: Whether to sort descending (default True, newest first)

    Returns:
        Tuple of (modified query, cursor_info dict)

    Example:
        query = select(ScanResult).where(...)
        query, cursor_info = apply_cursor_pagination(
            query, ScanResult, pagination,
            sort_column=ScanResult.scanned_at,
        )
        results = await session.execute(query)
        ...
    """
    # Default columns
    if sort_column is None:
        # Try common timestamp columns
        if hasattr(model, "scanned_at"):
            sort_column = model.scanned_at
        elif hasattr(model, "created_at"):
            sort_column = model.created_at
        else:
            raise ValueError(f"No default sort column found for {model.__name__}")

    if id_column is None:
        id_column = model.id

    # Apply cursor filter if cursor provided
    cursor_data = None
    if pagination.cursor:
        cursor_data = decode_cursor(pagination.cursor)
        if cursor_data:
            # Parse sort value back to datetime if needed
            sort_value = cursor_data.sort_value
            if isinstance(sort_value, str):
                try:
                    sort_value = datetime.fromisoformat(sort_value)
                except ValueError:
                    pass  # Keep as string

            # Apply seek condition
            # For descending: WHERE (sort_col, id) < (cursor_sort, cursor_id)
            # For ascending: WHERE (sort_col, id) > (cursor_sort, cursor_id)
            if sort_desc:
                # Descending order: get items "before" the cursor (smaller values)
                query = query.where(
                    (sort_column < sort_value)
                    | ((sort_column == sort_value) & (id_column < cursor_data.id_value))
                )
            else:
                # Ascending order: get items "after" the cursor (larger values)
                query = query.where(
                    (sort_column > sort_value)
                    | ((sort_column == sort_value) & (id_column > cursor_data.id_value))
                )

    # Apply ordering
    if sort_desc:
        query = query.order_by(desc(sort_column), desc(id_column))
    else:
        query = query.order_by(asc(sort_column), asc(id_column))

    # Fetch one extra to check if there are more results
    query = query.limit(pagination.limit + 1)

    cursor_info = {
        "limit": pagination.limit,
        "include_total": pagination.include_total,
        "sort_column_name": sort_column.key,
        "sort_desc": sort_desc,
    }

    return query, cursor_info


def build_cursor_response(
    items: Sequence[Any],
    cursor_info: dict,
    total: Optional[int] = None,
) -> CursorPaginationMeta:
    """
    Build cursor pagination metadata from query results.

    Args:
        items: List of items returned from query (may include extra item for has_more check)
        cursor_info: Dict from apply_cursor_pagination
        total: Optional total count

    Returns:
        CursorPaginationMeta
    """
    limit = cursor_info["limit"]
    sort_column_name = cursor_info["sort_column_name"]
    sort_desc = cursor_info.get("sort_desc", True)

    # Check if there are more results
    has_more = len(items) > limit

    # Get the actual items (excluding the extra one used for has_more check)
    actual_items = items[:limit] if has_more else items

    # Build next cursor from last item
    next_cursor = None
    if has_more and actual_items:
        last_item = actual_items[-1]
        sort_value = getattr(last_item, sort_column_name)
        id_value = last_item.id
        next_cursor = encode_cursor(sort_value, id_value)

    return CursorPaginationMeta(
        cursor=next_cursor,
        has_more=has_more,
        total=total if cursor_info.get("include_total") else None,
    )


# =============================================================================
# HYBRID PAGINATION (supports both cursor and offset)
# =============================================================================


class HybridPaginationParams:
    """
    Dependency that supports both cursor and offset-based pagination.

    This allows gradual migration from offset to cursor-based pagination
    while maintaining backward compatibility.

    - If cursor is provided, uses cursor-based pagination
    - Otherwise, falls back to offset-based pagination

    Usage:
        @router.get("/items")
        async def list_items(pagination: HybridPaginationParams = Depends()):
            if pagination.is_cursor_based:
                # Use cursor pagination
                ...
            else:
                # Use offset pagination
                ...
    """

    def __init__(
        self,
        cursor: Optional[str] = Query(
            None,
            description="Cursor for next page (takes precedence over page)",
        ),
        page: int = Query(1, ge=1, description="Page number (ignored if cursor provided)"),
        page_size: int = Query(50, ge=1, le=100, alias="limit", description="Items per page"),
        include_total: bool = Query(
            True,
            description="Include total count in response",
        ),
    ):
        self.cursor = cursor
        self.page = page
        self.page_size = page_size
        self.include_total = include_total

    @property
    def is_cursor_based(self) -> bool:
        """Whether this request uses cursor-based pagination."""
        return self.cursor is not None

    @property
    def offset(self) -> int:
        """Calculate offset for offset-based pagination."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Alias for page_size."""
        return self.page_size

    def to_cursor_params(self) -> CursorPaginationParams:
        """Convert to CursorPaginationParams."""
        return CursorPaginationParams(
            cursor=self.cursor,
            limit=self.page_size,
            include_total=self.include_total,
        )

    def to_offset_params(self) -> PaginationParams:
        """Convert to PaginationParams."""
        return PaginationParams(page=self.page, page_size=self.page_size)
