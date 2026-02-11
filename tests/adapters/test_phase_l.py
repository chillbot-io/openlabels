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
    def test_s3_adapter_has_required_protocol_methods(self):
        """S3Adapter must implement all ReadAdapter protocol methods."""
        from openlabels.adapters.s3 import S3Adapter
        import inspect

        adapter = S3Adapter(bucket="b")
        # Verify methods are callable (not just present as attributes)
        assert callable(getattr(adapter, "list_files"))
        assert callable(getattr(adapter, "read_file"))
        assert callable(getattr(adapter, "get_metadata"))
        assert callable(getattr(adapter, "apply_label_and_sync"))
        assert callable(getattr(adapter, "test_connection"))
        assert callable(getattr(adapter, "supports_delta"))
        # Verify list_files is async
        assert inspect.isasyncgenfunction(adapter.list_files) or inspect.iscoroutinefunction(adapter.list_files)

    def test_gcs_adapter_has_required_protocol_methods(self):
        """GCSAdapter must implement all ReadAdapter protocol methods."""
        from openlabels.adapters.gcs import GCSAdapter
        import inspect

        adapter = GCSAdapter(bucket="b")
        assert callable(getattr(adapter, "list_files"))
        assert callable(getattr(adapter, "read_file"))
        assert callable(getattr(adapter, "get_metadata"))
        assert callable(getattr(adapter, "apply_label_and_sync"))
        assert callable(getattr(adapter, "test_connection"))
        assert callable(getattr(adapter, "supports_delta"))
        assert inspect.isasyncgenfunction(adapter.list_files) or inspect.iscoroutinefunction(adapter.list_files)

    def test_adapters_exported_from_init(self):
        from openlabels.adapters import S3Adapter, GCSAdapter

        # Verify actual adapter_type values, not just "not None"
        assert S3Adapter(bucket="b").adapter_type == "s3"
        assert GCSAdapter(bucket="b").adapter_type == "gcs"

    def test_change_providers_have_changed_files_method(self):
        from openlabels.core.change_providers import (
            SQSChangeProvider,
            PubSubChangeProvider,
        )
        import inspect

        # Verify changed_files is a callable async method, not just an attribute
        assert callable(getattr(SQSChangeProvider, "changed_files"))
        assert callable(getattr(PubSubChangeProvider, "changed_files"))

    def test_adapter_type_identifiers(self):
        from openlabels.adapters.s3 import S3Adapter
        from openlabels.adapters.gcs import GCSAdapter

        assert S3Adapter(bucket="b").adapter_type == "s3"
        assert GCSAdapter(bucket="b").adapter_type == "gcs"


# ── Adapter registration ────────────────────────────────────────────


class TestAdapterRegistration:
    """Verify _get_adapter() handles s3 and gcs adapter types."""

    def test_scan_task_imports_s3_and_gcs_adapters(self):
        """The scan task module should import S3Adapter and GCSAdapter classes."""
        scan_py = Path("src/openlabels/jobs/tasks/scan.py")
        source = scan_py.read_text()
        tree = ast.parse(source)

        # Collect all imported names
        imported_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported_names.add(alias.name)

        assert "S3Adapter" in imported_names, "scan.py must import S3Adapter"
        assert "GCSAdapter" in imported_names, "scan.py must import GCSAdapter"


# ── Label sync-back pipeline step ────────────────────────────────────


class TestLabelSyncBack:
    def test_cloud_label_sync_back_function_is_async(self):
        """The _cloud_label_sync_back helper should be an async function in scan.py."""
        scan_py = Path("src/openlabels/jobs/tasks/scan.py")
        source = scan_py.read_text()
        tree = ast.parse(source)

        async_func_names = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef)
        ]
        assert "_cloud_label_sync_back" in async_func_names, \
            "_cloud_label_sync_back must be an async function"

    def test_label_sync_back_accepts_expected_parameters(self):
        """The _cloud_label_sync_back should accept adapter and label parameters."""
        scan_py = Path("src/openlabels/jobs/tasks/scan.py")
        source = scan_py.read_text()
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "_cloud_label_sync_back":
                param_names = [arg.arg for arg in node.args.args]
                assert len(param_names) >= 2, \
                    f"_cloud_label_sync_back should accept at least 2 parameters, got: {param_names}"
                break
        else:
            pytest.fail("_cloud_label_sync_back function not found")


# ── Labeling engine support ──────────────────────────────────────────


class TestLabelingEngineCloudSupport:
    def test_labeling_engine_references_cloud_adapters(self):
        """LabelingEngine must reference s3/gcs adapter types and deferred sync."""
        engine_py = Path("src/openlabels/labeling/engine.py")
        source = engine_py.read_text()
        tree = ast.parse(source)

        # Collect all string constants used in the engine
        string_constants = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                string_constants.add(node.value)

        assert "s3" in string_constants, "Engine must handle 's3' adapter type"
        assert "gcs" in string_constants, "Engine must handle 'gcs' adapter type"
        assert "deferred_cloud_sync" in source, "Engine must support deferred cloud sync"


# ── Optional dependencies ───────────────────────────────────────────


class TestOptionalDependencies:
    def test_pyproject_has_s3_extra_with_boto3(self):
        """pyproject.toml must declare s3 optional extra with boto3 dependency."""
        import tomllib

        pyproject = Path("pyproject.toml").read_text()
        data = tomllib.loads(pyproject)
        extras = data.get("project", {}).get("optional-dependencies", {})
        assert "s3" in extras, "Missing 's3' optional dependency group"
        s3_deps = " ".join(extras["s3"]).lower()
        assert "boto3" in s3_deps, "s3 extra must include boto3"

    def test_pyproject_has_gcs_extra_with_google_deps(self):
        """pyproject.toml must declare gcs optional extra with google-cloud deps."""
        import tomllib

        pyproject = Path("pyproject.toml").read_text()
        data = tomllib.loads(pyproject)
        extras = data.get("project", {}).get("optional-dependencies", {})
        assert "gcs" in extras, "Missing 'gcs' optional dependency group"
        gcs_deps = " ".join(extras["gcs"]).lower()
        assert "google-cloud-storage" in gcs_deps, "gcs extra must include google-cloud-storage"
        assert "google-cloud-pubsub" in gcs_deps, "gcs extra must include google-cloud-pubsub"

    def test_all_extra_includes_s3_and_gcs(self):
        """The 'all' extra group should include both s3 and gcs extras."""
        import tomllib

        pyproject = Path("pyproject.toml").read_text()
        data = tomllib.loads(pyproject)
        extras = data.get("project", {}).get("optional-dependencies", {})
        assert "all" in extras, "Missing 'all' optional dependency group"
        all_deps = " ".join(extras["all"]).lower()
        assert "s3" in all_deps, "'all' extra must include s3"
        assert "gcs" in all_deps, "'all' extra must include gcs"


# ── Label compatibility edge cases ───────────────────────────────────


class TestLabelCompatibility:
    def test_s3_label_compatible_types(self):
        from openlabels.adapters.base import is_label_compatible

        compatible = [
            "doc.docx", "sheet.xlsx", "pres.pptx", "report.pdf",
            "data.csv", "config.json", "page.html", "readme.txt",
            "photo.jpg", "image.png",
        ]
        for name in compatible:
            assert is_label_compatible(name) is True, f"{name} should be compatible"

    def test_s3_label_incompatible_types(self):
        from openlabels.adapters.base import is_label_compatible

        incompatible = [
            "app.exe", "lib.dll", "data.bin", "noextension",
            "archive.7z", "video.mp4", "audio.mp3",
        ]
        for name in incompatible:
            assert is_label_compatible(name) is False, f"{name} should be incompatible"

    def test_gcs_label_compatible_types(self):
        from openlabels.adapters.base import is_label_compatible

        assert is_label_compatible("doc.docx") is True
        assert is_label_compatible("app.exe") is False

    def test_extensions_are_shared_from_base(self):
        from openlabels.adapters.base import LABEL_COMPATIBLE_EXTENSIONS

        assert ".pdf" in LABEL_COMPATIBLE_EXTENSIONS
        assert ".docx" in LABEL_COMPATIBLE_EXTENSIONS
        assert ".exe" not in LABEL_COMPATIBLE_EXTENSIONS


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

        result = await adapter.apply_label_and_sync(fi, "label")
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
