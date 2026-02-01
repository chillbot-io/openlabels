"""File upload routes."""

import asyncio
import logging
from typing import Optional
from fastapi import APIRouter, Depends, UploadFile, File, Query, Request
from fastapi.responses import Response

from ...core import ScrubIQ
from ...constants import MAX_PAGINATION_LIMIT, MAX_FILE_SIZE_BYTES, API_RATE_WINDOW_SECONDS
from ...rate_limiter import check_rate_limit
from ..dependencies import require_unlocked
from ..errors import (
    bad_request, not_found, payload_too_large, server_error, service_unavailable,
    ErrorCode,
)
from .schemas import (
    UploadResponse, UploadStatusResponse, UploadResultResponse, SpanInfo,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["files"])

# File upload rate limiting: 20 uploads per minute per IP
UPLOAD_RATE_LIMIT = 20
UPLOAD_RATE_WINDOW_SECONDS = 60
# File read rate limiting
FILE_READ_RATE_LIMIT = 120  # Max file reads per window


@router.post("/upload", response_model=UploadResponse)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    conversation_id: Optional[str] = None,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """Upload a file for processing."""
    # Rate limit file uploads to prevent abuse
    check_rate_limit(
        request,
        action="upload",
        limit=UPLOAD_RATE_LIMIT,
        window_seconds=UPLOAD_RATE_WINDOW_SECONDS,
    )

    from ...files.validators import validate_file, FileValidationError, sanitize_filename

    # SECURITY: Check Content-Length header BEFORE reading file to prevent OOM
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            size = int(content_length)
            if size > MAX_FILE_SIZE_BYTES:
                raise payload_too_large(
                    f"File too large. Maximum size is {MAX_FILE_SIZE_BYTES // (1024*1024)}MB",
                    error_code=ErrorCode.FILE_TOO_LARGE,
                )
        except ValueError:
            pass  # Invalid Content-Length, will be caught by validate_file

    content = await file.read()
    safe_filename = sanitize_filename(file.filename or "unknown")

    try:
        # SECURITY FIX: Pass file_content to enable magic byte validation
        # This prevents attackers from uploading malicious files by
        # spoofing Content-Type headers.
        # validate_file now returns the corrected MIME type based on actual
        # file content (magic bytes), not just the browser-reported type.
        # PERFORMANCE FIX: Run blocking validation in thread pool to avoid blocking event loop
        validated_content_type = await asyncio.to_thread(
            validate_file,
            filename=safe_filename,
            content_type=file.content_type,
            size_bytes=len(content),
            file_content=content,  # Enable magic byte validation
        )
        # Use detected content type if available, otherwise fall back to browser-reported
        actual_content_type = validated_content_type or file.content_type
    except FileValidationError as e:
        raise bad_request(str(e), error_code=ErrorCode.VALIDATION_ERROR)

    try:
        job_id = cr.process_file_async(
            content=content,
            filename=safe_filename,
            content_type=actual_content_type,
            conversation_id=conversation_id,
        )
    except RuntimeError as e:
        error_msg = str(e)
        if "MODELS_LOADING" in error_msg:
            raise service_unavailable(
                "File processing is initializing. Please wait a moment and try again.",
                error_code=ErrorCode.MODELS_LOADING,
            )
        elif "not initialized" in error_msg:
            raise service_unavailable(
                "File processor not available. Please restart the application.",
                error_code=ErrorCode.INITIALIZING,
            )
        else:
            # SECURITY FIX: Don't leak internal error details to client
            # Log the full error internally for debugging
            logger.error(f"File processing error: {error_msg}")
            raise server_error(
                "File processing failed. Please try again or contact support.",
                error_code=ErrorCode.PROCESSING_ERROR,
            )

    return UploadResponse(job_id=job_id, filename=safe_filename, status="queued")


@router.get("/uploads/{job_id}", response_model=UploadStatusResponse)
def get_upload_status(request: Request, job_id: str, cr: ScrubIQ = Depends(require_unlocked)):
    """Get upload processing status."""
    check_rate_limit(request, action="file_read", limit=FILE_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    job = cr.get_upload_job(job_id)
    if not job:
        raise not_found("Upload not found", error_code=ErrorCode.UPLOAD_NOT_FOUND)

    return UploadStatusResponse(
        job_id=job["job_id"],
        filename=job["filename"],
        status=job["status"],
        progress=job["progress"],
        pages_total=job.get("pages_total"),
        pages_processed=job.get("pages_processed"),
        phi_count=job.get("phi_count"),
        error=job.get("error"),
    )


@router.get("/uploads/{job_id}/result", response_model=UploadResultResponse)
def get_upload_result(request: Request, job_id: str, cr: ScrubIQ = Depends(require_unlocked)):
    """Get completed upload results including redacted text and spans."""
    check_rate_limit(request, action="file_read", limit=FILE_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    result = cr.get_upload_result(job_id)
    if not result:
        raise not_found("Upload not found or not complete", error_code=ErrorCode.UPLOAD_NOT_FOUND)

    return UploadResultResponse(
        job_id=result["job_id"],
        filename=result["filename"],
        redacted_text=result["redacted_text"],
        spans=[SpanInfo(
            start=s["start"],
            end=s["end"],
            text=s.get("text", ""),
            entity_type=s["entity_type"],
            confidence=s["confidence"],
            detector=s["detector"],
            token=s.get("token"),
        ) for s in result["spans"]],
        pages=result.get("pages", 1),
        processing_time_ms=result.get("processing_time_ms", 0),
        ocr_confidence=result.get("ocr_confidence"),
        has_redacted_image=result.get("has_redacted_image", False),
    )


@router.get("/uploads/{job_id}/image")
def download_redacted_image(request: Request, job_id: str, cr: ScrubIQ = Depends(require_unlocked)):
    """Download redacted image for completed upload."""
    check_rate_limit(request, action="file_read", limit=FILE_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    result = cr.get_redacted_image(job_id)
    if not result:
        raise not_found("No redacted image available", error_code=ErrorCode.UPLOAD_NOT_FOUND)

    image_bytes, filename, content_type = result
    return Response(
        content=image_bytes,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="redacted_{filename}"'}
    )


@router.get("/uploads/{job_id}/pdf")
def download_redacted_pdf(request: Request, job_id: str, cr: ScrubIQ = Depends(require_unlocked)):
    """Download redacted PDF for completed upload."""
    check_rate_limit(request, action="file_read", limit=FILE_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    result = cr.get_redacted_image(job_id)
    if not result:
        raise not_found("No redacted file available", error_code=ErrorCode.UPLOAD_NOT_FOUND)

    file_bytes, filename, content_type = result

    if content_type == "application/pdf":
        return Response(
            content=file_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="redacted_{filename}"'}
        )
    else:
        return Response(
            content=file_bytes,
            media_type=content_type,
            headers={"Content-Disposition": f'inline; filename="redacted_{filename}"'}
        )


@router.get("/uploads")
def list_uploads(
    request: Request,
    conversation_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=MAX_PAGINATION_LIMIT),
    cr: ScrubIQ = Depends(require_unlocked),
):
    """List upload jobs."""
    check_rate_limit(request, action="file_read", limit=FILE_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    return cr.list_upload_jobs(conversation_id=conversation_id, limit=limit)
