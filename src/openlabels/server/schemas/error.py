"""
Standardized error response schemas for API responses.

This module contains Pydantic models for error responses,
ensuring consistent error handling across all API endpoints.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ErrorResponse(BaseModel):
    """
    Standardized error response format for all API endpoints.

    This model ensures consistent error responses across the entire API,
    making it easier for clients to handle errors programmatically.

    Attributes:
        error: Error code in SCREAMING_SNAKE_CASE (e.g., "VALIDATION_ERROR", "NOT_FOUND")
        message: Human-readable error message suitable for display
        details: Optional dictionary with additional context about the error
        request_id: Optional request correlation ID for tracing/debugging
    """

    error: str = Field(
        ...,
        description="Error code in SCREAMING_SNAKE_CASE",
        examples=["VALIDATION_ERROR", "NOT_FOUND", "INTERNAL_ERROR"],
    )
    message: str = Field(
        ...,
        description="Human-readable error message",
        examples=["The requested resource was not found"],
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description="Additional error context and details",
        examples=[{"field": "email", "reason": "Invalid format"}],
    )
    request_id: str | None = Field(
        default=None,
        description="Request correlation ID for tracing",
        examples=["abc123ef"],
    )

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "error": "NOT_FOUND",
            "message": "The requested resource was not found",
            "details": {"resource_type": "User", "resource_id": "123e4567-e89b-12d3-a456-426614174000"},
            "request_id": "abc123ef",
        }
    })


class SuccessResponse(BaseModel):
    """
    Generic success response for operations that don't return specific data.

    Attributes:
        message: Human-readable success message
        details: Optional dictionary with additional context
    """

    message: str = Field(
        ...,
        description="Human-readable success message",
        examples=["Operation completed successfully"],
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description="Additional context about the operation",
    )
