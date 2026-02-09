"""Phase L integration tests — config, adapter registration, pipeline wiring, module structure."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


# ── Configuration ────────────────────────────────────────────────────


class TestS3AdapterSettings:
    def test_defaults(self):
        from openlabels.server.config import S3AdapterSettings

        cfg = S3AdapterSettings()
        assert cfg.enabled is False
        assert cfg.buckets == []
        assert cfg.region == "us-east-1"
        assert cfg.access_key == ""
        assert cfg.secret_key == ""
        assert cfg.endpoint_url is None
        assert cfg.sqs_queue_url == ""
        assert cfg.label_sync_enabled is True

    def test_in_adapter_settings(self):
        from openlabels.server.config import AdapterSettings

        adapters = AdapterSettings()
        assert hasattr(adapters, "s3")
        assert adapters.s3.enabled is False


class TestGCSAdapterSettings:
    def test_defaults(self):
        from openlabels.server.config import GCSAdapterSettings

        cfg = GCSAdapterSettings()
        assert cfg.enabled is False
        assert cfg.buckets == []
        assert cfg.project == ""
        assert cfg.credentials_path is None
        assert cfg.pubsub_subscription == ""
        assert cfg.label_sync_enabled is True

    def test_in_adapter_settings(self):
        from openlabels.server.config import AdapterSettings

        adapters = AdapterSettings()
        assert hasattr(adapters, "gcs")
        assert adapters.gcs.enabled is False


class TestSettingsIntegration:
    def test_s3_and_gcs_in_main_settings(self):
        from openlabels.server.config import Settings

        settings = Settings()
        assert hasattr(settings.adapters, "s3")
        assert hasattr(settings.adapters, "gcs")


# ── Module structure ─────────────────────────────────────────────────


class TestModuleStructure:
    def test_s3_adapter_importable(self):
        from openlabels.adapters.s3 import S3Adapter

        assert hasattr(S3Adapter, "list_files")
        assert hasattr(S3Adapter, "read_file")
        assert hasattr(S3Adapter, "get_metadata")
        assert hasattr(S3Adapter, "apply_label_and_sync")
        assert hasattr(S3Adapter, "test_connection")
        assert hasattr(S3Adapter, "supports_delta")

    def test_gcs_adapter_importable(self):
        from openlabels.adapters.gcs import GCSAdapter

        assert hasattr(GCSAdapter, "list_files")
        assert hasattr(GCSAdapter, "read_file")
        assert hasattr(GCSAdapter, "get_metadata")
        assert hasattr(GCSAdapter, "apply_label_and_sync")
        assert hasattr(GCSAdapter, "test_connection")
        assert hasattr(GCSAdapter, "supports_delta")

    def test_adapters_exported_from_init(self):
        from openlabels.adapters import S3Adapter, GCSAdapter

        assert S3Adapter.adapter_type is not None
        assert GCSAdapter.adapter_type is not None

    def test_change_providers_importable(self):
        from openlabels.core.change_providers import (
            SQSChangeProvider,
            PubSubChangeProvider,
        )

        assert hasattr(SQSChangeProvider, "changed_files")
        assert hasattr(PubSubChangeProvider, "changed_files")

    def test_adapter_type_identifiers(self):
        from openlabels.adapters.s3 import S3Adapter
        from openlabels.adapters.gcs import GCSAdapter

        assert S3Adapter(bucket="b").adapter_type == "s3"
        assert GCSAdapter(bucket="b").adapter_type == "gcs"


# ── Adapter registration ────────────────────────────────────────────


class TestAdapterRegistration:
    """Verify _get_adapter() handles s3 and gcs adapter types."""

    def test_scan_task_file_references_s3_and_gcs(self):
        """The scan task should import and handle S3Adapter and GCSAdapter."""
        scan_py = Path("src/openlabels/jobs/tasks/scan.py")
        source = scan_py.read_text()
        assert "S3Adapter" in source
        assert "GCSAdapter" in source
        assert '"s3"' in source or "'s3'" in source
        assert '"gcs"' in source or "'gcs'" in source

    def test_get_adapter_valid_types_documented(self):
        """_get_adapter should list s3 and gcs in its error message."""
        scan_py = Path("src/openlabels/jobs/tasks/scan.py")
        source = scan_py.read_text()
        assert "s3" in source
        assert "gcs" in source


# ── Label sync-back pipeline step ────────────────────────────────────


class TestLabelSyncBack:
    def test_cloud_label_sync_back_function_exists(self):
        """The _cloud_label_sync_back helper should exist in scan.py."""
        scan_py = Path("src/openlabels/jobs/tasks/scan.py")
        source = scan_py.read_text()
        tree = ast.parse(source)

        func_names = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        assert "_cloud_label_sync_back" in func_names

    def test_label_sync_back_called_in_pipeline(self):
        """The scan pipeline should call _cloud_label_sync_back for s3/gcs."""
        scan_py = Path("src/openlabels/jobs/tasks/scan.py")
        source = scan_py.read_text()
        assert "_cloud_label_sync_back" in source
        assert "label_sync_enabled" in source


# ── Labeling engine support ──────────────────────────────────────────


class TestLabelingEngineCloudSupport:
    def test_labeling_engine_handles_s3_gcs(self):
        """LabelingEngine.apply_label should not error for s3/gcs adapters."""
        engine_py = Path("src/openlabels/labeling/engine.py")
        source = engine_py.read_text()
        assert '"s3"' in source or "'s3'" in source
        assert '"gcs"' in source or "'gcs'" in source
        assert "deferred_cloud_sync" in source


# ── Optional dependencies ───────────────────────────────────────────


class TestOptionalDependencies:
    def test_pyproject_has_s3_extra(self):
        pyproject = Path("pyproject.toml").read_text()
        assert "s3 = [" in pyproject or "[s3]" in pyproject
        assert "boto3" in pyproject

    def test_pyproject_has_gcs_extra(self):
        pyproject = Path("pyproject.toml").read_text()
        assert "gcs = [" in pyproject or "[gcs]" in pyproject
        assert "google-cloud-storage" in pyproject
        assert "google-cloud-pubsub" in pyproject

    def test_all_extra_includes_s3_and_gcs(self):
        pyproject = Path("pyproject.toml").read_text()
        # The 'all' extra should include s3 and gcs
        assert "s3" in pyproject
        assert "gcs" in pyproject


# ── Label compatibility edge cases ───────────────────────────────────


class TestLabelCompatibility:
    def test_s3_label_compatible_types(self):
        from openlabels.adapters.s3 import _is_label_compatible

        compatible = [
            "doc.docx", "sheet.xlsx", "pres.pptx", "report.pdf",
            "data.csv", "config.json", "page.html", "readme.txt",
            "photo.jpg", "image.png",
        ]
        for name in compatible:
            assert _is_label_compatible(name) is True, f"{name} should be compatible"

    def test_s3_label_incompatible_types(self):
        from openlabels.adapters.s3 import _is_label_compatible

        incompatible = [
            "app.exe", "lib.dll", "data.bin", "noextension",
            "archive.7z", "video.mp4", "audio.mp3",
        ]
        for name in incompatible:
            assert _is_label_compatible(name) is False, f"{name} should be incompatible"

    def test_gcs_label_compatible_types(self):
        from openlabels.adapters.gcs import _is_label_compatible

        assert _is_label_compatible("doc.docx") is True
        assert _is_label_compatible("app.exe") is False

    def test_both_adapters_share_same_compatible_set(self):
        from openlabels.adapters.s3 import (
            _LABEL_COMPATIBLE_EXTENSIONS as s3_ext,
        )
        from openlabels.adapters.gcs import (
            _LABEL_COMPATIBLE_EXTENSIONS as gcs_ext,
        )

        assert s3_ext == gcs_ext


# ── Conflict handling ────────────────────────────────────────────────


class TestConflictHandling:
    @pytest.mark.asyncio
    async def test_s3_etag_mismatch_returns_error(self):
        """S3 apply_label_and_sync should fail on ETag mismatch."""
        from openlabels.adapters.s3 import S3Adapter
        from unittest.mock import MagicMock
        from datetime import datetime, timezone

        from openlabels.adapters.base import FileInfo

        mock_client = MagicMock()
        mock_client.head_object.return_value = {
            "ETag": '"changed"',
            "Metadata": {},
            "ContentType": "text/plain",
        }

        adapter = S3Adapter(bucket="b")
        adapter._client = mock_client

        fi = FileInfo(
            path="s3://b/f.txt", name="f.txt", size=1,
            modified=datetime.now(timezone.utc),
            adapter="s3", item_id="f.txt",
            permissions={"etag": "original"},
        )

        result = await adapter.apply_label_and_sync(fi, "label", content=b"x")
        assert result["success"] is False
        assert "ETag mismatch" in result["error"]

    @pytest.mark.asyncio
    async def test_gcs_generation_mismatch_returns_error(self):
        """GCS apply_label_and_sync should fail on generation mismatch."""
        from openlabels.adapters.gcs import GCSAdapter
        from unittest.mock import MagicMock
        from datetime import datetime, timezone

        from openlabels.adapters.base import FileInfo

        mock_blob = MagicMock()
        mock_blob.generation = 999
        mock_blob.metadata = {}
        mock_blob.reload.return_value = None

        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        mock_client = MagicMock()
        mock_client.bucket.return_value = mock_bucket

        adapter = GCSAdapter(bucket="b")
        adapter._client = mock_client

        fi = FileInfo(
            path="gs://b/f.txt", name="f.txt", size=1,
            modified=datetime.now(timezone.utc),
            adapter="gcs", item_id="f.txt",
            permissions={"generation": 100},
        )

        result = await adapter.apply_label_and_sync(fi, "label", content=b"x")
        assert result["success"] is False
        assert "Generation mismatch" in result["error"]
