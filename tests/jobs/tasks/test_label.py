"""
Comprehensive tests for the label application task.

Tests focus on:
- Label task execution
- Routing to appropriate labeling method
- Local file labeling (MIP and metadata fallback)
- Office document metadata handling
- PDF metadata handling
- Sidecar file creation
- Graph API labeling
"""

import sys
import os
import json
import tempfile
import zipfile

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from unittest.mock import MagicMock, AsyncMock, patch

from openlabels.jobs.tasks.label import (
    execute_label_task,
    _apply_label,
    _apply_label_local,
    _apply_label_metadata,
    _apply_label_sidecar,
    _create_custom_props_xml,
    _update_custom_props_xml,
    _update_content_types,
    HTTPX_AVAILABLE,
)


class TestExecuteLabelTask:
    """Tests for execute_label_task function."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_result(self):
        """Create a mock ScanResult."""
        result = MagicMock()
        result.id = uuid4()
        result.file_path = "/test/document.docx"
        result.label_applied = False
        result.label_applied_at = None
        result.current_label_id = None
        result.current_label_name = None
        result.label_error = None
        return result

    @pytest.fixture
    def mock_label(self):
        """Create a mock SensitivityLabel."""
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Confidential"
        return label

    async def test_raises_when_result_not_found(self, mock_session):
        """Should raise ValueError when result doesn't exist."""
        mock_session.get = AsyncMock(return_value=None)

        with pytest.raises(ValueError) as exc_info:
            await execute_label_task(
                mock_session,
                {"result_id": str(uuid4()), "label_id": str(uuid4())}
            )

        assert "Result not found" in str(exc_info.value)

    async def test_raises_when_label_not_found(self, mock_session, mock_result):
        """Should raise ValueError when label doesn't exist."""
        mock_session.get = AsyncMock(side_effect=[mock_result, None])

        with pytest.raises(ValueError) as exc_info:
            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": str(uuid4())}
            )

        assert "Label not found" in str(exc_info.value)

    async def test_returns_success_on_successful_labeling(self, mock_session, mock_result, mock_label):
        """Should return success result when labeling succeeds."""
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch('openlabels.jobs.tasks.label._apply_label') as mock_apply:
            mock_apply.return_value = {"success": True, "method": "test"}

            result = await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id}
            )

            assert result["success"] is True
            assert result["label_name"] == "Confidential"
            assert mock_result.label_applied is True

    async def test_returns_failure_on_labeling_error(self, mock_session, mock_result, mock_label):
        """Should return failure result when labeling fails."""
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch('openlabels.jobs.tasks.label._apply_label') as mock_apply:
            mock_apply.return_value = {
                "success": False,
                "method": "test",
                "error": "Test error"
            }

            result = await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id}
            )

            assert result["success"] is False
            assert result["error"] == "Test error"
            assert mock_result.label_applied is False


class TestApplyLabel:
    """Tests for _apply_label routing function."""

    @pytest.fixture
    def mock_result(self):
        """Create a mock ScanResult."""
        result = MagicMock()
        result.file_path = "/test/file.txt"
        return result

    @pytest.fixture
    def mock_label(self):
        """Create a mock SensitivityLabel."""
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Confidential"
        return label

    async def test_routes_sharepoint_to_graph(self, mock_result, mock_label):
        """Should route SharePoint URLs to Graph API."""
        mock_result.file_path = "https://contoso.sharepoint.com/sites/docs/file.docx"

        with patch('openlabels.jobs.tasks.label._apply_label_graph') as mock_graph:
            mock_graph.return_value = {"success": True, "method": "graph"}

            result = await _apply_label(mock_result, mock_label)

            mock_graph.assert_called_once()

    async def test_routes_onedrive_to_graph(self, mock_result, mock_label):
        """Should route OneDrive URLs to Graph API."""
        mock_result.file_path = "https://contoso-my.sharepoint.com/personal/user_onedrive/file.xlsx"

        with patch('openlabels.jobs.tasks.label._apply_label_graph') as mock_graph:
            mock_graph.return_value = {"success": True, "method": "graph"}

            result = await _apply_label(mock_result, mock_label)

            mock_graph.assert_called_once()

    async def test_rejects_non_microsoft_urls(self, mock_result, mock_label):
        """Should reject non-Microsoft HTTP URLs."""
        mock_result.file_path = "https://example.com/files/document.pdf"

        result = await _apply_label(mock_result, mock_label)

        assert result["success"] is False
        assert result["method"] == "unsupported"

    async def test_routes_local_files_to_local(self, mock_result, mock_label):
        """Should route local file paths to local labeling."""
        mock_result.file_path = "/home/user/document.docx"

        with patch('openlabels.jobs.tasks.label._apply_label_local') as mock_local:
            mock_local.return_value = {"success": True, "method": "local"}

            result = await _apply_label(mock_result, mock_label)

            mock_local.assert_called_once()


class TestApplyLabelLocal:
    """Tests for local file labeling."""

    @pytest.fixture
    def mock_result(self):
        """Create a mock ScanResult."""
        result = MagicMock()
        return result

    @pytest.fixture
    def mock_label(self):
        """Create a mock SensitivityLabel."""
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Confidential"
        return label

    async def test_returns_error_for_missing_file(self, mock_result, mock_label):
        """Should return error when file doesn't exist."""
        mock_result.file_path = "/nonexistent/path/file.txt"

        result = await _apply_label_local(mock_result, mock_label)

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    async def test_tries_mip_first(self, mock_result, mock_label):
        """Should try MIP SDK before metadata."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as f:
            f.write(b"test")
            temp_path = f.name

        try:
            mock_result.file_path = temp_path

            with patch('openlabels.jobs.tasks.label._apply_label_mip') as mock_mip:
                mock_mip.return_value = {"success": True, "method": "mip"}

                result = await _apply_label_local(mock_result, mock_label)

                mock_mip.assert_called_once()
                assert result["success"] is True
        finally:
            os.unlink(temp_path)

    async def test_falls_back_to_metadata_when_mip_unavailable(self, mock_result, mock_label):
        """Should fall back to metadata when MIP not available."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content")
            temp_path = f.name

        try:
            mock_result.file_path = temp_path

            with patch('openlabels.jobs.tasks.label._apply_label_mip') as mock_mip:
                mock_mip.return_value = {
                    "success": False,
                    "method": "mip",
                    "error": "MIP SDK not available"
                }
                with patch('openlabels.jobs.tasks.label._apply_label_metadata') as mock_meta:
                    mock_meta.return_value = {"success": True, "method": "metadata"}

                    result = await _apply_label_local(mock_result, mock_label)

                    mock_meta.assert_called_once()
        finally:
            os.unlink(temp_path)


class TestApplyLabelMetadata:
    """Tests for metadata-based labeling."""

    @pytest.fixture
    def mock_label(self):
        """Create a mock SensitivityLabel."""
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Confidential"
        return label

    async def test_routes_docx_to_office_metadata(self, mock_label):
        """Should route .docx files to Office metadata labeling."""
        with patch('openlabels.jobs.tasks.label._apply_label_office_metadata') as mock_office:
            mock_office.return_value = {"success": True, "method": "office_metadata"}

            result = await _apply_label_metadata("/path/doc.docx", mock_label)

            mock_office.assert_called_once()

    async def test_routes_xlsx_to_office_metadata(self, mock_label):
        """Should route .xlsx files to Office metadata labeling."""
        with patch('openlabels.jobs.tasks.label._apply_label_office_metadata') as mock_office:
            mock_office.return_value = {"success": True, "method": "office_metadata"}

            result = await _apply_label_metadata("/path/sheet.xlsx", mock_label)

            mock_office.assert_called_once()

    async def test_routes_pptx_to_office_metadata(self, mock_label):
        """Should route .pptx files to Office metadata labeling."""
        with patch('openlabels.jobs.tasks.label._apply_label_office_metadata') as mock_office:
            mock_office.return_value = {"success": True, "method": "office_metadata"}

            result = await _apply_label_metadata("/path/slides.pptx", mock_label)

            mock_office.assert_called_once()

    async def test_routes_pdf_to_pdf_metadata(self, mock_label):
        """Should route .pdf files to PDF metadata labeling."""
        with patch('openlabels.jobs.tasks.label._apply_label_pdf_metadata') as mock_pdf:
            mock_pdf.return_value = {"success": True, "method": "pdf_metadata"}

            result = await _apply_label_metadata("/path/doc.pdf", mock_label)

            mock_pdf.assert_called_once()

    async def test_routes_other_to_sidecar(self, mock_label):
        """Should route other file types to sidecar labeling."""
        with patch('openlabels.jobs.tasks.label._apply_label_sidecar') as mock_sidecar:
            mock_sidecar.return_value = {"success": True, "method": "sidecar"}

            result = await _apply_label_metadata("/path/data.csv", mock_label)

            mock_sidecar.assert_called_once()


class TestApplyLabelSidecar:
    """Tests for sidecar file creation."""

    @pytest.fixture
    def mock_label(self):
        """Create a mock SensitivityLabel."""
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Confidential"
        return label

    async def test_creates_sidecar_file(self, mock_label):
        """Should create a sidecar file with label information."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as f:
            f.write(b"data,data")
            temp_path = f.name

        sidecar_path = temp_path + ".openlabels"

        try:
            result = await _apply_label_sidecar(temp_path, mock_label)

            assert result["success"] is True
            assert result["method"] == "sidecar"
            assert os.path.exists(sidecar_path)

            # Verify sidecar content
            with open(sidecar_path) as f:
                sidecar_data = json.load(f)

            assert sidecar_data["label_id"] == mock_label.id
            assert sidecar_data["label_name"] == mock_label.name
            assert "applied_at" in sidecar_data

        finally:
            os.unlink(temp_path)
            if os.path.exists(sidecar_path):
                os.unlink(sidecar_path)

    async def test_sidecar_includes_applied_by(self, mock_label):
        """Sidecar should include applied_by field."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test")
            temp_path = f.name

        sidecar_path = temp_path + ".openlabels"

        try:
            await _apply_label_sidecar(temp_path, mock_label)

            with open(sidecar_path) as f:
                sidecar_data = json.load(f)

            assert sidecar_data["applied_by"] == "OpenLabels"

        finally:
            os.unlink(temp_path)
            if os.path.exists(sidecar_path):
                os.unlink(sidecar_path)


class TestCreateCustomPropsXml:
    """Tests for Office custom properties XML creation."""

    @pytest.fixture
    def mock_label(self):
        """Create a mock SensitivityLabel."""
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Highly Confidential"
        return label

    def test_creates_valid_xml(self, mock_label):
        """Should create valid XML with label properties."""
        xml_bytes = _create_custom_props_xml(mock_label)

        assert b"<?xml version" in xml_bytes
        assert b"OpenLabels_LabelId" in xml_bytes
        assert b"OpenLabels_LabelName" in xml_bytes
        assert b"Classification" in xml_bytes

    def test_includes_label_id(self, mock_label):
        """Should include the label ID in XML."""
        xml_bytes = _create_custom_props_xml(mock_label)

        assert mock_label.id.encode() in xml_bytes

    def test_includes_label_name(self, mock_label):
        """Should include the label name in XML."""
        xml_bytes = _create_custom_props_xml(mock_label)

        assert mock_label.name.encode() in xml_bytes

    def test_returns_bytes(self, mock_label):
        """Should return bytes, not string."""
        result = _create_custom_props_xml(mock_label)

        assert isinstance(result, bytes)


class TestUpdateCustomPropsXml:
    """Tests for updating existing custom properties XML."""

    @pytest.fixture
    def mock_label(self):
        """Create a mock SensitivityLabel."""
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Updated Label"
        return label

    def test_updates_existing_properties(self, mock_label):
        """Should update existing label properties."""
        existing_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
    <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="OpenLabels_LabelId">
        <vt:lpwstr>old-id</vt:lpwstr>
    </property>
</Properties>"""

        result = _update_custom_props_xml(existing_xml.encode(), mock_label)

        assert mock_label.id.encode() in result
        assert b"old-id" not in result

    def test_adds_missing_properties(self, mock_label):
        """Should add properties that don't exist."""
        existing_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
    <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="OtherProp">
        <vt:lpwstr>value</vt:lpwstr>
    </property>
</Properties>"""

        result = _update_custom_props_xml(existing_xml.encode(), mock_label)

        assert b"OpenLabels_LabelId" in result
        assert b"OpenLabels_LabelName" in result

    def test_handles_invalid_xml(self, mock_label):
        """Should fall back to creating new XML on parse error."""
        invalid_xml = b"<not valid xml"

        result = _update_custom_props_xml(invalid_xml, mock_label)

        # Should have created new XML
        assert b"<?xml version" in result
        assert b"OpenLabels_LabelId" in result


class TestUpdateContentTypes:
    """Tests for content types XML update."""

    def test_adds_custom_props_content_type(self):
        """Should add content type for custom properties."""
        content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="xml" ContentType="application/xml"/>
</Types>"""

        result = _update_content_types(content_types.encode())

        assert b"/docProps/custom.xml" in result
        assert b"custom-properties+xml" in result

    def test_does_not_duplicate_existing(self):
        """Should not add if custom props type already exists."""
        content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
</Types>"""

        result = _update_content_types(content_types.encode())

        # Count occurrences - should be exactly 1
        count = result.count(b"/docProps/custom.xml")
        assert count == 1


class TestHttpxAvailability:
    """Tests for HTTPX availability flag."""

    def test_httpx_available_is_boolean(self):
        """HTTPX_AVAILABLE should be a boolean."""
        assert isinstance(HTTPX_AVAILABLE, bool)


class TestGraphApiLabeling:
    """Tests for Graph API labeling (requires httpx mocking)."""

    @pytest.fixture
    def mock_result(self):
        """Create a mock ScanResult."""
        result = MagicMock()
        result.file_path = "https://contoso.sharepoint.com/sites/team/Shared Documents/file.docx"
        return result

    @pytest.fixture
    def mock_label(self):
        """Create a mock SensitivityLabel."""
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Confidential"
        return label

    async def test_returns_error_when_httpx_unavailable(self, mock_result, mock_label):
        """Should return error when httpx is not installed."""
        import openlabels.jobs.tasks.label as label_module
        original = label_module.HTTPX_AVAILABLE

        try:
            label_module.HTTPX_AVAILABLE = False

            from openlabels.jobs.tasks.label import _apply_label_graph
            result = await _apply_label_graph(mock_result, mock_label)

            assert result["success"] is False
            assert "httpx" in result["error"]
        finally:
            label_module.HTTPX_AVAILABLE = original


class TestLabelPayloadParsing:
    """Tests for payload parsing in label task."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        return AsyncMock()

    async def test_parses_result_id_from_payload(self, mock_session):
        """Should parse result_id from payload."""
        result_id = uuid4()
        mock_session.get = AsyncMock(return_value=None)

        with pytest.raises(ValueError):
            await execute_label_task(
                mock_session,
                {"result_id": str(result_id), "label_id": str(uuid4())}
            )

        # Verify the UUID was parsed correctly
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        assert call_args[0][1] == result_id

    async def test_parses_label_id_from_payload(self, mock_session):
        """Should parse label_id from payload."""
        result_id = uuid4()
        label_id = str(uuid4())

        mock_result = MagicMock()
        mock_result.id = result_id
        mock_session.get = AsyncMock(side_effect=[mock_result, None])

        with pytest.raises(ValueError):
            await execute_label_task(
                mock_session,
                {"result_id": str(result_id), "label_id": label_id}
            )

        # Second call should be for the label
        assert mock_session.get.call_count == 2


class TestLabelResultUpdate:
    """Tests for scan result update after labeling."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_result(self):
        """Create a mock ScanResult."""
        result = MagicMock()
        result.id = uuid4()
        result.file_path = "/test/file.docx"
        result.label_applied = False
        result.label_applied_at = None
        result.current_label_id = None
        result.current_label_name = None
        result.label_error = None
        return result

    @pytest.fixture
    def mock_label(self):
        """Create a mock SensitivityLabel."""
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Secret"
        return label

    async def test_updates_label_applied_on_success(self, mock_session, mock_result, mock_label):
        """Should set label_applied=True on success."""
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch('openlabels.jobs.tasks.label._apply_label') as mock_apply:
            mock_apply.return_value = {"success": True, "method": "test"}

            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id}
            )

            assert mock_result.label_applied is True

    async def test_updates_label_applied_at_on_success(self, mock_session, mock_result, mock_label):
        """Should set label_applied_at timestamp on success."""
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch('openlabels.jobs.tasks.label._apply_label') as mock_apply:
            mock_apply.return_value = {"success": True, "method": "test"}

            before = datetime.now(timezone.utc)
            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id}
            )
            after = datetime.now(timezone.utc)

            assert before <= mock_result.label_applied_at <= after

    async def test_updates_current_label_on_success(self, mock_session, mock_result, mock_label):
        """Should update current_label_id and current_label_name on success."""
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch('openlabels.jobs.tasks.label._apply_label') as mock_apply:
            mock_apply.return_value = {"success": True, "method": "test"}

            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id}
            )

            assert mock_result.current_label_id == mock_label.id
            assert mock_result.current_label_name == "Secret"

    async def test_clears_label_error_on_success(self, mock_session, mock_result, mock_label):
        """Should clear label_error on success."""
        mock_result.label_error = "Previous error"
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch('openlabels.jobs.tasks.label._apply_label') as mock_apply:
            mock_apply.return_value = {"success": True, "method": "test"}

            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id}
            )

            assert mock_result.label_error is None

    async def test_sets_label_error_on_failure(self, mock_session, mock_result, mock_label):
        """Should set label_error on failure."""
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch('openlabels.jobs.tasks.label._apply_label') as mock_apply:
            mock_apply.return_value = {
                "success": False,
                "method": "test",
                "error": "Labeling failed"
            }

            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id}
            )

            assert mock_result.label_error == "Labeling failed"
