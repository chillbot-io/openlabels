"""
Server schemas for request/response models.

This module contains Pydantic models for API standardization.
"""

from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    CursorPaginationParams,
    CursorPaginatedResponse,
    paginate_query,
    cursor_paginate_query,
)
from openlabels.server.schemas.error import (
    ErrorResponse,
    SuccessResponse,
)

__all__ = [
    # Pagination
    "PaginatedResponse",
    "PaginationParams",
    "CursorPaginationParams",
    "CursorPaginatedResponse",
    "paginate_query",
    "cursor_paginate_query",
    # Error responses
    "ErrorResponse",
    "SuccessResponse",
]
