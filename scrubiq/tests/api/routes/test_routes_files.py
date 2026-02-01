"""Tests for files API routes: upload, status, results, downloads.

Tests file upload and processing endpoints.

Note: These tests require SQLCipher and FastAPI to be installed.
"""

import io
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

try:
    from scrubiq.api.routes import files as routes_files
    SCRUBIQ_AVAILABLE = True
except (ImportError, RuntimeError):
    SCRUBIQ_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not SCRUBIQ_AVAILABLE,
    reason="ScrubIQ package not available (missing SQLCipher or other dependencies)"
)

from fastapi import FastAPI
from fastapi.testclient import TestClient


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def mock_scrubiq():
    """Create a mock ScrubIQ instance."""
    mock = MagicMock()

    # Upload job
    mock.process_file_async.return_value = "job-123"

    # Job status
    mock.get_upload_job.return_value = {
        "job_id": "job-123",
        "filename": "test.pdf",
        "status": "processing",
        "progress": 0.5,
        "pages_total": 10,
        "pages_processed": 5,
        "phi_count": 15,
    }

    # Job result
    mock.get_upload_result.return_value = {
        "job_id": "job-123",
        "filename": "test.pdf",
        "redacted_text": "Patient [NAME_1] visited on [DATE_1]",
        "spans": [
            {"start": 8, "end": 16, "text": "[NAME_1]", "entity_type": "NAME",
             "confidence": 0.95, "detector": "ml", "token": "[NAME_1]"},
        ],
        "pages": 10,
        "processing_time_ms": 5000.0,
        "ocr_confidence": 0.92,
        "has_redacted_image": True,
    }

    # Redacted image
    mock.get_redacted_image.return_value = (
        b"fake image bytes",
        "test.pdf",
        "application/pdf",
    )

    # List jobs
    mock.list_upload_jobs.return_value = [
        {"job_id": "job-123", "filename": "test.pdf", "status": "complete"},
    ]

    return mock


@pytest.fixture
def client(mock_scrubiq):
    """Create test client with mocked dependencies."""
    from scrubiq.api.routes.files import router
    from scrubiq.api.dependencies import require_unlocked
    from scrubiq.api.errors import register_error_handlers

    app = FastAPI()
    app.include_router(router)
    register_error_handlers(app)

    app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

    with patch("scrubiq.api.routes.files.check_rate_limit"):
        yield TestClient(app, raise_server_exceptions=False)


# =============================================================================
# UPLOAD ENDPOINT TESTS
# =============================================================================

class TestUploadEndpoint:
    """Tests for POST /upload endpoint."""

    def test_upload_success(self, client, mock_scrubiq):
        """Upload returns job ID."""
        with patch("scrubiq.api.routes.files.validate_file", return_value="application/pdf"):
            response = client.post(
                "/upload",
                files={"file": ("test.pdf", b"PDF content", "application/pdf")},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == "job-123"
        assert data["status"] == "queued"

    def test_upload_returns_filename(self, client, mock_scrubiq):
        """Upload returns sanitized filename."""
        with patch("scrubiq.api.routes.files.validate_file", return_value="application/pdf"):
            with patch("scrubiq.api.routes.files.sanitize_filename", return_value="safe_name.pdf"):
                response = client.post(
                    "/upload",
                    files={"file": ("test.pdf", b"content", "application/pdf")},
                )

        assert response.status_code == 200
        assert response.json()["filename"] == "safe_name.pdf"

    def test_upload_calls_process_async(self, client, mock_scrubiq):
        """Upload calls process_file_async."""
        with patch("scrubiq.api.routes.files.validate_file", return_value="application/pdf"):
            with patch("scrubiq.api.routes.files.sanitize_filename", return_value="test.pdf"):
                client.post(
                    "/upload",
                    files={"file": ("test.pdf", b"content", "application/pdf")},
                )

        mock_scrubiq.process_file_async.assert_called_once()
        call_kwargs = mock_scrubiq.process_file_async.call_args[1]
        assert call_kwargs["filename"] == "test.pdf"
        assert call_kwargs["content"] == b"content"

    def test_upload_with_conversation_id(self, client, mock_scrubiq):
        """Upload passes conversation_id."""
        with patch("scrubiq.api.routes.files.validate_file", return_value="application/pdf"):
            with patch("scrubiq.api.routes.files.sanitize_filename", return_value="test.pdf"):
                client.post(
                    "/upload?conversation_id=conv-123",
                    files={"file": ("test.pdf", b"content", "application/pdf")},
                )

        call_kwargs = mock_scrubiq.process_file_async.call_args[1]
        assert call_kwargs["conversation_id"] == "conv-123"

    def test_upload_validation_error(self, client, mock_scrubiq):
        """Upload returns 400 for invalid file."""
        from scrubiq.files.validators import FileValidationError

        with patch("scrubiq.api.routes.files.validate_file", side_effect=FileValidationError("Invalid file type")):
            with patch("scrubiq.api.routes.files.sanitize_filename", return_value="test.exe"):
                response = client.post(
                    "/upload",
                    files={"file": ("test.exe", b"content", "application/octet-stream")},
                )

        assert response.status_code == 400
        assert "VALIDATION_ERROR" in response.json()["error_code"]

    def test_upload_models_loading(self, client, mock_scrubiq):
        """Upload returns 503 when models loading."""
        with patch("scrubiq.api.routes.files.validate_file", return_value="application/pdf"):
            with patch("scrubiq.api.routes.files.sanitize_filename", return_value="test.pdf"):
                mock_scrubiq.process_file_async.side_effect = RuntimeError("MODELS_LOADING")

                response = client.post(
                    "/upload",
                    files={"file": ("test.pdf", b"content", "application/pdf")},
                )

        assert response.status_code == 503
        assert "MODELS_LOADING" in response.json()["error_code"]


# =============================================================================
# STATUS ENDPOINT TESTS
# =============================================================================

class TestUploadStatusEndpoint:
    """Tests for GET /uploads/{job_id} endpoint."""

    def test_status_success(self, client, mock_scrubiq):
        """Status returns job status."""
        response = client.get("/uploads/job-123")

        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == "job-123"
        assert data["status"] == "processing"

    def test_status_includes_progress(self, client, mock_scrubiq):
        """Status includes progress info."""
        response = client.get("/uploads/job-123")

        assert response.status_code == 200
        data = response.json()
        assert data["progress"] == 0.5
        assert data["pages_total"] == 10
        assert data["pages_processed"] == 5

    def test_status_includes_phi_count(self, client, mock_scrubiq):
        """Status includes PHI count."""
        response = client.get("/uploads/job-123")

        assert response.json()["phi_count"] == 15

    def test_status_not_found(self, client, mock_scrubiq):
        """Status returns 404 for unknown job."""
        mock_scrubiq.get_upload_job.return_value = None

        response = client.get("/uploads/unknown-job")

        assert response.status_code == 404
        assert "UPLOAD_NOT_FOUND" in response.json()["error_code"]


# =============================================================================
# RESULT ENDPOINT TESTS
# =============================================================================

class TestUploadResultEndpoint:
    """Tests for GET /uploads/{job_id}/result endpoint."""

    def test_result_success(self, client, mock_scrubiq):
        """Result returns completed job data."""
        response = client.get("/uploads/job-123/result")

        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == "job-123"
        assert "redacted_text" in data

    def test_result_includes_spans(self, client, mock_scrubiq):
        """Result includes detected spans."""
        response = client.get("/uploads/job-123/result")

        assert response.status_code == 200
        spans = response.json()["spans"]
        assert len(spans) == 1
        assert spans[0]["entity_type"] == "NAME"

    def test_result_includes_metadata(self, client, mock_scrubiq):
        """Result includes processing metadata."""
        response = client.get("/uploads/job-123/result")

        data = response.json()
        assert data["pages"] == 10
        assert data["processing_time_ms"] == 5000.0
        assert data["ocr_confidence"] == 0.92
        assert data["has_redacted_image"] is True

    def test_result_not_found(self, client, mock_scrubiq):
        """Result returns 404 for unknown or incomplete job."""
        mock_scrubiq.get_upload_result.return_value = None

        response = client.get("/uploads/unknown-job/result")

        assert response.status_code == 404


# =============================================================================
# IMAGE DOWNLOAD ENDPOINT TESTS
# =============================================================================

class TestImageDownloadEndpoint:
    """Tests for GET /uploads/{job_id}/image endpoint."""

    def test_image_download_success(self, client, mock_scrubiq):
        """Image download returns file content."""
        mock_scrubiq.get_redacted_image.return_value = (
            b"PNG image data",
            "test.png",
            "image/png",
        )

        response = client.get("/uploads/job-123/image")

        assert response.status_code == 200
        assert response.content == b"PNG image data"

    def test_image_download_content_type(self, client, mock_scrubiq):
        """Image download sets correct content type."""
        mock_scrubiq.get_redacted_image.return_value = (
            b"PNG data",
            "test.png",
            "image/png",
        )

        response = client.get("/uploads/job-123/image")

        assert response.headers["content-type"] == "image/png"

    def test_image_download_disposition(self, client, mock_scrubiq):
        """Image download sets Content-Disposition."""
        mock_scrubiq.get_redacted_image.return_value = (
            b"data",
            "test.png",
            "image/png",
        )

        response = client.get("/uploads/job-123/image")

        assert "attachment" in response.headers["content-disposition"]
        assert "redacted_test.png" in response.headers["content-disposition"]

    def test_image_download_not_found(self, client, mock_scrubiq):
        """Image download returns 404 when no image."""
        mock_scrubiq.get_redacted_image.return_value = None

        response = client.get("/uploads/job-123/image")

        assert response.status_code == 404


# =============================================================================
# PDF DOWNLOAD ENDPOINT TESTS
# =============================================================================

class TestPdfDownloadEndpoint:
    """Tests for GET /uploads/{job_id}/pdf endpoint."""

    def test_pdf_download_success(self, client, mock_scrubiq):
        """PDF download returns file content."""
        response = client.get("/uploads/job-123/pdf")

        assert response.status_code == 200
        assert response.content == b"fake image bytes"

    def test_pdf_download_inline_disposition(self, client, mock_scrubiq):
        """PDF download uses inline disposition."""
        response = client.get("/uploads/job-123/pdf")

        assert "inline" in response.headers["content-disposition"]

    def test_pdf_download_not_found(self, client, mock_scrubiq):
        """PDF download returns 404 when no file."""
        mock_scrubiq.get_redacted_image.return_value = None

        response = client.get("/uploads/job-123/pdf")

        assert response.status_code == 404


# =============================================================================
# LIST UPLOADS ENDPOINT TESTS
# =============================================================================

class TestListUploadsEndpoint:
    """Tests for GET /uploads endpoint."""

    def test_list_success(self, client, mock_scrubiq):
        """List uploads returns job list."""
        response = client.get("/uploads")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_list_with_conversation_filter(self, client, mock_scrubiq):
        """List uploads filters by conversation_id."""
        client.get("/uploads?conversation_id=conv-123")

        mock_scrubiq.list_upload_jobs.assert_called_once()
        call_kwargs = mock_scrubiq.list_upload_jobs.call_args[1]
        assert call_kwargs["conversation_id"] == "conv-123"

    def test_list_with_limit(self, client, mock_scrubiq):
        """List uploads respects limit."""
        client.get("/uploads?limit=10")

        call_kwargs = mock_scrubiq.list_upload_jobs.call_args[1]
        assert call_kwargs["limit"] == 10

    def test_list_job_structure(self, client, mock_scrubiq):
        """Listed jobs have correct structure."""
        response = client.get("/uploads")

        job = response.json()[0]
        assert job["job_id"] == "job-123"
        assert job["filename"] == "test.pdf"
        assert job["status"] == "complete"
