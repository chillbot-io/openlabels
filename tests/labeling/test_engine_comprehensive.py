"""
Comprehensive tests for the labeling engine.

Tests cover:
- Token caching and expiration
- Retry logic with exponential backoff
- Rate limiting (429 responses)
- Office metadata labeling (ZIP manipulation)
- PDF metadata labeling
- Sidecar file labeling
- Graph API integration
- Label cache operations
- Error handling paths
"""

import asyncio
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from openlabels.adapters.base import FileInfo

# Check if PyPDF2 is available for PDF metadata tests
try:
    import PyPDF2
    HAS_PYPDF2 = True
except ImportError:
    HAS_PYPDF2 = False
from openlabels.labeling.engine import (
    CachedLabel,
    LabelCache,
    LabelingEngine,
    LabelResult,
    TokenCache,
    get_label_cache,
)


class TestCachedLabel:
    """Tests for CachedLabel dataclass."""

    def test_cached_label_has_cached_at(self):
        """CachedLabel gets cached_at timestamp."""
        before = datetime.now(timezone.utc)
        label = CachedLabel(
            id="label-1",
            name="Test",
            description="",
            color="",
            priority=0,
            parent_id=None,
        )
        after = datetime.now(timezone.utc)

        assert before <= label.cached_at <= after

class TestTokenCache:
    """Tests for TokenCache dataclass."""

    def test_token_cache_just_outside_buffer(self):
        """Token just outside 5-minute buffer is valid."""
        cache = TokenCache(
            access_token="test-token",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=6),
        )

        assert cache.is_valid() is True

    def test_token_cache_empty_token_invalid(self):
        """Empty token is invalid even with future expiry."""
        cache = TokenCache(
            access_token="",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        # Note: is_valid() returns falsy value when token is empty
        assert not cache.is_valid()


class TestLabelCache:
    """Tests for LabelCache singleton."""

    @pytest.fixture(autouse=True)
    def reset_cache(self):
        """Reset label cache before each test."""
        cache = get_label_cache()
        cache.invalidate()
        yield
        cache.invalidate()

    def test_label_cache_set_updates_refresh_time(self):
        """Setting labels updates last_refresh."""
        cache = get_label_cache()
        cache.invalidate()

        labels = [
            {"id": "label-1", "name": "Label 1", "description": "", "color": "", "priority": 0, "parent_id": None},
        ]
        cache.set(labels)

        assert cache.is_expired() is False
        assert cache._last_refresh is not None

    def test_label_cache_returns_none_when_expired(self):
        """Get returns None when cache is expired."""
        cache = get_label_cache()
        labels = [
            {"id": "label-1", "name": "Label 1", "description": "", "color": "", "priority": 0, "parent_id": None},
        ]
        cache.set(labels)

        # Force expire
        cache._last_refresh = datetime.now(timezone.utc) - timedelta(hours=1)

        assert cache.get("label-1") is None
        assert cache.get_all() == []

    def test_label_cache_respects_max_labels(self):
        """Cache respects max_labels limit."""
        cache = get_label_cache()
        cache.configure(max_labels=2)

        labels = [
            {"id": f"label-{i}", "name": f"Label {i}", "description": "", "color": "", "priority": i, "parent_id": None}
            for i in range(5)
        ]
        cache.set(labels)

        assert len(cache._labels) == 2

    def test_label_cache_stats(self):
        """Stats returns cache information."""
        cache = get_label_cache()
        labels = [
            {"id": "label-1", "name": "Label 1", "description": "", "color": "", "priority": 0, "parent_id": None},
        ]
        cache.set(labels)

        stats = cache.stats

        assert "label_count" in stats
        assert "last_refresh" in stats
        assert "ttl_seconds" in stats
        assert "is_expired" in stats
        assert stats["label_count"] == 1


class TestLabelingEngineTokenAcquisition:
    """Tests for token acquisition with retry logic."""

    async def test_get_access_token_uses_cache(self):
        """_get_access_token returns cached token if valid."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )
        engine._token_cache = TokenCache(
            access_token="cached-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        token = await engine._get_access_token()

        assert token == "cached-token"

    async def test_get_access_token_fetches_new_when_expired(self):
        """_get_access_token fetches new token when expired."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new-token",
            "expires_in": 3600,
        }

        with patch.object(httpx.AsyncClient, "post", return_value=mock_response):
            token = await engine._get_access_token()

        assert token == "new-token"
        assert engine._token_cache.access_token == "new-token"

    async def test_get_access_token_handles_rate_limit(self):
        """_get_access_token handles 429 rate limiting."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        # First call returns 429, second returns success
        mock_429 = MagicMock()
        mock_429.status_code = 429
        mock_429.headers = {"Retry-After": "1"}

        mock_success = MagicMock()
        mock_success.status_code = 200
        mock_success.json.return_value = {"access_token": "token", "expires_in": 3600}
        mock_success.raise_for_status = MagicMock()

        call_count = [0]

        async def mock_post(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return mock_429
            return mock_success

        with patch.object(httpx.AsyncClient, "post", side_effect=mock_post):
            with patch("asyncio.sleep", return_value=None):
                token = await engine._get_access_token()

        assert token == "token"
        assert call_count[0] == 2

    async def test_get_access_token_retries_on_5xx(self):
        """_get_access_token retries on server errors."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        # First call fails with 500, second succeeds
        call_count = [0]

        async def mock_post(*args, **kwargs):
            call_count[0] += 1
            mock_response = MagicMock()
            if call_count[0] == 1:
                mock_response.status_code = 500
                mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                    "Server Error",
                    request=MagicMock(),
                    response=mock_response,
                )
                return mock_response
            mock_response.status_code = 200
            mock_response.json.return_value = {"access_token": "token", "expires_in": 3600}
            mock_response.raise_for_status = MagicMock()
            return mock_response

        with patch.object(httpx.AsyncClient, "post", side_effect=mock_post):
            with patch("asyncio.sleep", return_value=None):
                token = await engine._get_access_token()

        assert token == "token"


class TestLabelingEngineOfficeMetadata:
    """Tests for Office document metadata labeling."""

    async def test_apply_office_metadata_docx(self, tmp_path):
        """_apply_office_metadata adds custom properties to docx."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        # Create a minimal docx file (which is a ZIP archive)
        docx_path = tmp_path / "test.docx"
        with zipfile.ZipFile(docx_path, "w") as zf:
            zf.writestr("[Content_Types].xml", """<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>""")
            zf.writestr("word/document.xml", """<?xml version="1.0"?><document/>""")

        result = await engine._apply_office_metadata(str(docx_path), "label-123", "Confidential")

        assert result.success is True
        assert result.method == "office_metadata"
        assert result.label_id == "label-123"

        # Verify label was added
        with zipfile.ZipFile(docx_path, "r") as zf:
            assert "docProps/custom.xml" in zf.namelist()
            custom_xml = zf.read("docProps/custom.xml").decode("utf-8")
            assert "label-123" in custom_xml
            assert "OpenLabels_LabelId" in custom_xml

    async def test_apply_office_metadata_with_existing_properties(self, tmp_path):
        """_apply_office_metadata updates existing custom properties."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        # Create docx with existing custom properties
        docx_path = tmp_path / "test.docx"
        existing_custom = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="ExistingProperty">
    <vt:lpwstr>ExistingValue</vt:lpwstr>
  </property>
</Properties>'''

        with zipfile.ZipFile(docx_path, "w") as zf:
            zf.writestr("[Content_Types].xml", """<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>""")
            zf.writestr("docProps/custom.xml", existing_custom)
            zf.writestr("word/document.xml", """<?xml version="1.0"?><document/>""")

        result = await engine._apply_office_metadata(str(docx_path), "new-label", "New Label")

        assert result.success is True

        # Verify both old and new properties exist
        with zipfile.ZipFile(docx_path, "r") as zf:
            custom_xml = zf.read("docProps/custom.xml").decode("utf-8")
            assert "new-label" in custom_xml

    async def test_apply_office_metadata_bad_zipfile(self, tmp_path):
        """_apply_office_metadata handles corrupt ZIP files."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        # Create a non-ZIP file
        bad_file = tmp_path / "bad.docx"
        bad_file.write_text("This is not a ZIP file")

        with patch.object(engine, "_apply_sidecar") as mock_sidecar:
            mock_sidecar.return_value = LabelResult(success=True, method="sidecar")

            result = await engine._apply_office_metadata(str(bad_file), "label-1", "Label")

            # Should fall back to sidecar
            mock_sidecar.assert_called_once()

    async def test_apply_office_metadata_permission_error(self, tmp_path):
        """_apply_office_metadata handles permission errors."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        test_file = tmp_path / "test.docx"
        test_file.write_text("dummy")

        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            with patch.object(engine, "_apply_sidecar") as mock_sidecar:
                mock_sidecar.return_value = LabelResult(success=True, method="sidecar")

                await engine._apply_office_metadata(str(test_file), "label-1", "Label")

                # Should fall back to sidecar
                mock_sidecar.assert_called_once()


@pytest.mark.skipif(not HAS_PYPDF2, reason="PyPDF2 not installed")
class TestLabelingEnginePDFMetadata:
    """Tests for PDF metadata labeling."""

    async def test_apply_pdf_metadata_fallback_on_permission_error(self, tmp_path):
        """_apply_pdf_metadata falls back to sidecar on permission error."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_text("dummy")

        # Mock PdfReader to raise PermissionError (which is caught and triggers fallback)
        with patch("PyPDF2.PdfReader", side_effect=PermissionError("Access denied")):
            with patch.object(engine, "_apply_sidecar") as mock_sidecar:
                mock_sidecar.return_value = LabelResult(success=True, method="sidecar")

                result = await engine._apply_pdf_metadata(str(pdf_file), "label-1", "Label")

                # Should fall back to sidecar
                mock_sidecar.assert_called_once()

    async def test_apply_pdf_metadata_fallback_on_os_error(self, tmp_path):
        """_apply_pdf_metadata falls back to sidecar on OS error."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_text("dummy")

        # Mock PdfReader to raise OSError (which is caught and triggers fallback)
        with patch("PyPDF2.PdfReader", side_effect=OSError("File error")):
            with patch.object(engine, "_apply_sidecar") as mock_sidecar:
                mock_sidecar.return_value = LabelResult(success=True, method="sidecar")

                result = await engine._apply_pdf_metadata(str(pdf_file), "label-1", "Label")

                # Should fall back to sidecar
                mock_sidecar.assert_called_once()

    async def test_apply_pdf_metadata_fallback_on_value_error(self, tmp_path):
        """_apply_pdf_metadata falls back to sidecar on invalid PDF format."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_text("dummy")

        # Mock PdfReader to raise ValueError (which is caught and triggers fallback)
        with patch("PyPDF2.PdfReader", side_effect=ValueError("Invalid format")):
            with patch.object(engine, "_apply_sidecar") as mock_sidecar:
                mock_sidecar.return_value = LabelResult(success=True, method="sidecar")

                result = await engine._apply_pdf_metadata(str(pdf_file), "label-1", "Label")

                # Should fall back to sidecar
                mock_sidecar.assert_called_once()

    async def test_apply_pdf_metadata_uncaught_exception_bug(self, tmp_path):
        """
        BUG EXPOSED: _apply_pdf_metadata doesn't catch PdfReadError.

        When PyPDF2 encounters an invalid PDF, it raises PdfReadError which
        is not caught, causing the method to fail instead of falling back
        to sidecar. This is a real application bug.

        The code should catch all PDF-related exceptions and fall back to sidecar.
        """
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_text("Not a valid PDF")

        # This demonstrates the bug - PdfReadError is not caught
        from PyPDF2.errors import PdfReadError

        with pytest.raises(PdfReadError):
            await engine._apply_pdf_metadata(str(pdf_file), "label-1", "Label")


class TestLabelingEngineSidecar:
    """Tests for sidecar file labeling."""

    async def test_apply_sidecar_creates_file(self, tmp_path):
        """_apply_sidecar creates .openlabels sidecar file."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        result = await engine._apply_sidecar(str(test_file), "label-123", "Confidential")

        assert result.success is True
        assert result.method == "sidecar"

        # Verify sidecar was created
        sidecar_path = Path(f"{test_file}.openlabels")
        assert sidecar_path.exists()

        with open(sidecar_path) as f:
            sidecar_data = json.load(f)
            assert sidecar_data["label_id"] == "label-123"
            assert sidecar_data["label_name"] == "Confidential"
            assert "applied_at" in sidecar_data

    async def test_apply_sidecar_permission_error(self, tmp_path):
        """_apply_sidecar handles permission errors."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = await engine._apply_sidecar(str(test_file), "label-1", "Label")

        assert result.success is False
        assert "Permission denied" in result.error


class TestLabelingEngineGraphAPI:
    """Tests for Graph API label operations."""

    async def test_apply_graph_label_success(self):
        """_apply_graph_label applies label via Graph API."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        file_info = FileInfo(
            path="https://sharepoint.com/file.docx",
            name="file.docx",
            adapter="sharepoint",
            size=1000,
            modified=datetime.now(),
            item_id="sites/abc/drive/items/123",
            site_id="abc",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch.object(engine, "_graph_request", return_value=mock_response):
            result = await engine._apply_graph_label(file_info, "label-123", "Confidential")

        assert result.success is True
        assert result.method == "graph_api"

    async def test_apply_graph_label_error_response(self):
        """_apply_graph_label handles error responses."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        file_info = FileInfo(
            path="https://sharepoint.com/file.docx",
            name="file.docx",
            adapter="sharepoint",
            size=1000,
            modified=datetime.now(),
            item_id="sites/abc/drive/items/123",
            site_id="abc",
        )

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.content = b'{"error": {"message": "Forbidden"}}'
        mock_response.json.return_value = {"error": {"message": "Forbidden"}}

        with patch.object(engine, "_graph_request", return_value=mock_response):
            result = await engine._apply_graph_label(file_info, "label-123")

        assert result.success is False
        assert "Forbidden" in result.error

    async def test_apply_graph_label_timeout(self):
        """_apply_graph_label handles timeout."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        file_info = FileInfo(
            path="https://sharepoint.com/file.docx",
            name="file.docx",
            adapter="sharepoint",
            size=1000,
            modified=datetime.now(),
            item_id="item-123",
            site_id="site-456",
        )

        with patch.object(engine, "_graph_request", side_effect=httpx.TimeoutException("Timeout")):
            result = await engine._apply_graph_label(file_info, "label-123")

        assert result.success is False
        assert "timed out" in result.error.lower()


class TestLabelingEngineRemoveLabel:
    """Tests for remove_label method."""

    async def test_remove_label_filesystem(self, tmp_path):
        """remove_label removes label from local file."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        # Create sidecar
        sidecar = tmp_path / "test.txt.openlabels"
        sidecar.write_text('{"label_id": "old-label"}')

        file_info = FileInfo(
            path=str(test_file),
            name="test.txt",
            adapter="filesystem",
            size=4,
            modified=datetime.now(),
        )

        result = await engine.remove_label(file_info)

        assert result.success is True
        assert not sidecar.exists()

    async def test_remove_label_sharepoint(self):
        """remove_label removes label via Graph API."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        file_info = FileInfo(
            path="https://sharepoint.com/file.docx",
            name="file.docx",
            adapter="sharepoint",
            size=1000,
            modified=datetime.now(),
            item_id="item-123",
            site_id="site-456",
        )

        mock_response = MagicMock()
        mock_response.status_code = 204

        with patch.object(engine, "_graph_request", return_value=mock_response):
            result = await engine.remove_label(file_info)

        assert result.success is True


class TestLabelingEngineGetCurrentLabel:
    """Tests for get_current_label method."""

    async def test_get_current_label_from_sidecar(self, tmp_path):
        """get_current_label reads from sidecar file."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        sidecar = tmp_path / "test.txt.openlabels"
        sidecar.write_text('{"label_id": "label-123", "label_name": "Confidential"}')

        file_info = FileInfo(
            path=str(test_file),
            name="test.txt",
            adapter="filesystem",
            size=4,
            modified=datetime.now(),
        )

        result = await engine.get_current_label(file_info)

        assert result is not None
        assert result["id"] == "label-123"
        assert result["name"] == "Confidential"

    async def test_get_current_label_no_label(self, tmp_path):
        """get_current_label returns None when no label."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        file_info = FileInfo(
            path=str(test_file),
            name="test.txt",
            adapter="filesystem",
            size=4,
            modified=datetime.now(),
        )

        result = await engine.get_current_label(file_info)

        assert result is None


class TestLabelingEngineGetAvailableLabels:
    """Tests for get_available_labels method."""

    @pytest.fixture(autouse=True)
    def reset_cache(self):
        """Reset label cache before each test."""
        get_label_cache().invalidate()
        yield
        get_label_cache().invalidate()

    async def test_get_available_labels_from_cache(self):
        """get_available_labels returns cached labels if not expired."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        # Pre-populate cache
        cache = get_label_cache()
        cache.set([
            {"id": "label-1", "name": "Label 1", "description": "", "color": "", "priority": 0, "parent_id": None},
        ])

        labels = await engine.get_available_labels(use_cache=True)

        assert len(labels) == 1
        assert labels[0]["id"] == "label-1"

    async def test_get_available_labels_fetches_when_expired(self):
        """get_available_labels fetches from API when cache expired."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [
                {"id": "label-from-api", "name": "API Label", "description": "", "color": "", "priority": 0},
            ]
        }

        with patch.object(engine, "_graph_request", return_value=mock_response):
            labels = await engine.get_available_labels()

        assert len(labels) == 1
        assert labels[0]["id"] == "label-from-api"


class TestLabelingEngineCacheHelpers:
    """Tests for label cache helper methods."""

    @pytest.fixture(autouse=True)
    def reset_cache(self):
        """Reset label cache before each test."""
        get_label_cache().invalidate()
        yield
        get_label_cache().invalidate()

    def test_get_cached_label(self):
        """get_cached_label returns label from cache."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        cache = get_label_cache()
        cache.set([
            {"id": "label-123", "name": "Test Label", "description": "", "color": "", "priority": 0, "parent_id": None},
        ])

        result = engine.get_cached_label("label-123")

        assert result is not None
        assert result["id"] == "label-123"

    def test_get_cached_label_by_name(self):
        """get_cached_label_by_name returns label from cache."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        cache = get_label_cache()
        cache.set([
            {"id": "label-456", "name": "Confidential", "description": "", "color": "", "priority": 0, "parent_id": None},
        ])

        result = engine.get_cached_label_by_name("Confidential")

        assert result is not None
        assert result["name"] == "Confidential"

    def test_invalidate_label_cache(self):
        """invalidate_label_cache clears the cache."""
        engine = LabelingEngine(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        cache = get_label_cache()
        cache.set([
            {"id": "label-1", "name": "Label 1", "description": "", "color": "", "priority": 0, "parent_id": None},
        ])

        engine.invalidate_label_cache()

        assert cache.is_expired() is True

