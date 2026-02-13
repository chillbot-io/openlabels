"""
Standardized error codes for OpenLabels API.
"""

from __future__ import annotations

import logging
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorCode(str, Enum):
    """Standardized error codes for the API."""

    # General errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    BAD_REQUEST = "BAD_REQUEST"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    RATE_LIMITED = "RATE_LIMITED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"

    # Resource-specific errors
    SCAN_NOT_FOUND = "SCAN_NOT_FOUND"
    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
    RESULT_NOT_FOUND = "RESULT_NOT_FOUND"
    LABEL_NOT_FOUND = "LABEL_NOT_FOUND"
    RULE_NOT_FOUND = "RULE_NOT_FOUND"
    JOB_NOT_FOUND = "JOB_NOT_FOUND"
    USER_NOT_FOUND = "USER_NOT_FOUND"

    # Operation errors
    SCAN_CANNOT_CANCEL = "SCAN_CANNOT_CANCEL"
    SCAN_CANNOT_RETRY = "SCAN_CANNOT_RETRY"
    NO_RECOMMENDED_LABEL = "NO_RECOMMENDED_LABEL"
    TARGET_NOT_AVAILABLE = "TARGET_NOT_AVAILABLE"
    INVALID_RULE_TYPE = "INVALID_RULE_TYPE"

    # Integration errors
    DATABASE_ERROR = "DATABASE_ERROR"
    AZURE_AD_NOT_CONFIGURED = "AZURE_AD_NOT_CONFIGURED"
    HTTPX_NOT_AVAILABLE = "HTTPX_NOT_AVAILABLE"
    LABEL_SYNC_FAILED = "LABEL_SYNC_FAILED"
    CACHE_INVALIDATION_FAILED = "CACHE_INVALIDATION_FAILED"


def raise_database_error(operation: str, exc: Exception) -> None:
    """Log and raise a standardized database error.

    Replaces the repeated ``except SQLAlchemyError`` → ``InternalError``
    pattern found across route handlers.
    """
    from openlabels.exceptions import InternalError

    logger.error("Database error %s: %s", operation, exc)
    raise InternalError(
        message=f"Database error occurred while {operation}",
        details={"error_code": ErrorCode.DATABASE_ERROR},
    ) from exc
