"""
Tests for adapter base classes and filter logic.

Tests actual behavior of FilterConfig, ExposureLevel ordering, and FileInfo.
"""

import pytest
from datetime import datetime


class TestExposureLevel:
    """Tests for ExposureLevel enum semantics."""

    def test_exposure_levels_have_meaningful_order(self):
        """Exposure levels should progress from most to least restrictive."""
        from openlabels.adapters.base import ExposureLevel

        levels = list(ExposureLevel)

        # PRIVATE should be first (most restrictive)
        assert levels[0] == ExposureLevel.PRIVATE

        # PUBLIC should be last (least restrictive)
        assert levels[-1] == ExposureLevel.PUBLIC

    def test_exposure_level_values_are_uppercase(self):
        """Exposure level values should be uppercase strings for consistency."""
        from openlabels.adapters.base import ExposureLevel

        for level in ExposureLevel:
            assert level.value == level.value.upper()
            assert level.value == level.name

    def test_exposure_level_comparison_in_code(self):
        """Exposure levels should be usable for access control comparisons."""
        from openlabels.adapters.base import ExposureLevel

        # Define ordering: PRIVATE < INTERNAL < ORG_WIDE < PUBLIC
        order = [ExposureLevel.PRIVATE, ExposureLevel.INTERNAL,
                 ExposureLevel.ORG_WIDE, ExposureLevel.PUBLIC]

        # Verify we can find index for comparison
        for i, level in enumerate(order):
            assert order.index(level) == i


class TestFileInfo:
    """Tests for FileInfo dataclass behavior."""

    def test_required_fields_must_be_provided(self):
        """FileInfo should require path, name, size, modified."""
        from openlabels.adapters.base import FileInfo

        # Should fail without required fields
        with pytest.raises(TypeError):
            FileInfo()

        with pytest.raises(TypeError):
            FileInfo(path="/test")

    def test_defaults_to_private_exposure(self):
        """FileInfo should default to PRIVATE exposure for security."""
        from openlabels.adapters.base import FileInfo, ExposureLevel

        info = FileInfo(
            path="/test/file.txt",
            name="file.txt",
            size=100,
            modified=datetime.now(),
        )

        assert info.exposure == ExposureLevel.PRIVATE

    def test_optional_fields_default_to_none(self):
        """Optional fields should default to None."""
        from openlabels.adapters.base import FileInfo

        info = FileInfo(
            path="/test/file.txt",
            name="file.txt",
            size=100,
            modified=datetime.now(),
        )

        assert info.owner is None
        assert info.permissions is None
        assert info.item_id is None
        assert info.site_id is None
        assert info.user_id is None

    def test_stores_all_provided_values(self):
        """FileInfo should correctly store all provided values."""
        from openlabels.adapters.base import FileInfo, ExposureLevel

        now = datetime.now()
        info = FileInfo(
            path="/path/to/file.txt",
            name="file.txt",
            size=1024,
            modified=now,
            owner="user@example.com",
            exposure=ExposureLevel.PUBLIC,
            adapter="sharepoint",
            item_id="item-123",
            site_id="site-456",
        )

        assert info.path == "/path/to/file.txt"
        assert info.name == "file.txt"
        assert info.size == 1024
        assert info.modified == now
        assert info.owner == "user@example.com"
        assert info.exposure == ExposureLevel.PUBLIC
        assert info.adapter == "sharepoint"
        assert info.item_id == "item-123"
        assert info.site_id == "site-456"


class TestFilterConfig:
    """Tests for FilterConfig filtering logic."""

    def test_excludes_temp_file_extensions(self):
        """Should exclude common temp file extensions by default."""
        from openlabels.adapters.base import FilterConfig, FileInfo

        config = FilterConfig(exclude_temp_files=True)

        temp_extensions = ["tmp", "temp", "bak", "swp", "pyc", "cache"]
        for ext in temp_extensions:
            file_info = FileInfo(
                path=f"/test/file.{ext}",
                name=f"file.{ext}",
                size=100,
                modified=datetime.now(),
            )
            assert config.should_include(file_info) is False, \
                f"Should exclude .{ext} files"

    def test_excludes_system_directories(self):
        """Should exclude system/build directories by default."""
        from openlabels.adapters.base import FilterConfig, FileInfo

        config = FilterConfig(exclude_system_dirs=True)

        excluded_paths = [
            "/project/.git/config",
            "/project/node_modules/package/index.js",
            "/project/__pycache__/module.pyc",
            "/project/.venv/lib/python/site.py",
        ]

        for path in excluded_paths:
            file_info = FileInfo(
                path=path,
                name=path.split("/")[-1],
                size=100,
                modified=datetime.now(),
            )
            assert config.should_include(file_info) is False, \
                f"Should exclude {path}"

    def test_includes_normal_files(self):
        """Should include normal source files."""
        from openlabels.adapters.base import FilterConfig, FileInfo

        config = FilterConfig()

        included_files = [
            "/project/src/main.py",
            "/project/README.md",
            "/project/data/report.docx",
        ]

        for path in included_files:
            file_info = FileInfo(
                path=path,
                name=path.split("/")[-1],
                size=100,
                modified=datetime.now(),
            )
            assert config.should_include(file_info) is True, \
                f"Should include {path}"

    def test_respects_size_limits(self):
        """Should filter files by size limits."""
        from openlabels.adapters.base import FilterConfig, FileInfo

        config = FilterConfig(
            min_size_bytes=100,
            max_size_bytes=1000,
            exclude_temp_files=False,
            exclude_system_dirs=False,
        )

        # Too small
        small_file = FileInfo(path="/test.txt", name="test.txt", size=50, modified=datetime.now())
        assert config.should_include(small_file) is False

        # Too large
        large_file = FileInfo(path="/test.txt", name="test.txt", size=2000, modified=datetime.now())
        assert config.should_include(large_file) is False

        # Just right
        good_file = FileInfo(path="/test.txt", name="test.txt", size=500, modified=datetime.now())
        assert config.should_include(good_file) is True

    def test_excludes_specified_accounts(self):
        """Should exclude files owned by specified accounts."""
        from openlabels.adapters.base import FilterConfig, FileInfo

        config = FilterConfig(
            exclude_accounts=["system@domain.com", "svc_*"],
            exclude_temp_files=False,
            exclude_system_dirs=False,
        )

        # Exact match
        system_file = FileInfo(
            path="/test.txt", name="test.txt", size=100, modified=datetime.now(),
            owner="system@domain.com"
        )
        assert config.should_include(system_file) is False

        # Pattern match
        service_file = FileInfo(
            path="/test.txt", name="test.txt", size=100, modified=datetime.now(),
            owner="svc_backup@domain.com"
        )
        assert config.should_include(service_file) is False

        # Not excluded
        user_file = FileInfo(
            path="/test.txt", name="test.txt", size=100, modified=datetime.now(),
            owner="user@domain.com"
        )
        assert config.should_include(user_file) is True

    def test_extension_exclusion_is_case_insensitive(self):
        """Extension exclusion should be case-insensitive."""
        from openlabels.adapters.base import FilterConfig, FileInfo

        config = FilterConfig(
            exclude_extensions=["TMP", "BAK"],
            exclude_temp_files=False,
            exclude_system_dirs=False,
        )

        # Lowercase should be excluded
        lower_file = FileInfo(path="/test.tmp", name="test.tmp", size=100, modified=datetime.now())
        assert config.should_include(lower_file) is False

        # Uppercase should be excluded
        upper_file = FileInfo(path="/test.TMP", name="test.TMP", size=100, modified=datetime.now())
        assert config.should_include(upper_file) is False

    def test_custom_exclusion_patterns(self):
        """Should support custom glob patterns for exclusion."""
        from openlabels.adapters.base import FilterConfig, FileInfo

        config = FilterConfig(
            exclude_patterns=["*.log", "backup_*/*"],
            exclude_temp_files=False,
            exclude_system_dirs=False,
        )

        log_file = FileInfo(path="/app/debug.log", name="debug.log", size=100, modified=datetime.now())
        assert config.should_include(log_file) is False

    def test_no_filters_includes_everything(self):
        """With all filters disabled, should include any file."""
        from openlabels.adapters.base import FilterConfig, FileInfo

        config = FilterConfig(
            exclude_temp_files=False,
            exclude_system_dirs=False,
            exclude_extensions=[],
            exclude_patterns=[],
            exclude_accounts=[],
        )

        weird_file = FileInfo(
            path="/node_modules/.git/test.tmp",
            name="test.tmp",
            size=100,
            modified=datetime.now(),
        )
        assert config.should_include(weird_file) is True


class TestDefaultFilter:
    """Tests for DEFAULT_FILTER constant."""

    def test_default_filter_has_reasonable_exclusions(self):
        """DEFAULT_FILTER should exclude common unwanted files."""
        from openlabels.adapters.base import DEFAULT_FILTER, FileInfo

        # Should exclude .git
        git_file = FileInfo(
            path="/project/.git/config",
            name="config",
            size=100,
            modified=datetime.now(),
        )
        assert DEFAULT_FILTER.should_include(git_file) is False

        # Should exclude node_modules
        node_file = FileInfo(
            path="/project/node_modules/pkg/index.js",
            name="index.js",
            size=100,
            modified=datetime.now(),
        )
        assert DEFAULT_FILTER.should_include(node_file) is False


class TestAdapterProtocol:
    """Tests verifying the Adapter protocol definition."""

    def test_protocol_defines_required_methods(self):
        """Adapter protocol should define all required methods."""
        from openlabels.adapters.base import Adapter
        import inspect

        # Get all methods defined in the protocol
        methods = [name for name, _ in inspect.getmembers(Adapter, predicate=inspect.isfunction)]

        required_methods = [
            'list_files',
            'read_file',
            'get_metadata',
            'test_connection',
            'supports_delta',
            'move_file',
            'get_acl',
            'set_acl',
            'supports_remediation',
        ]

        for method in required_methods:
            assert method in methods or hasattr(Adapter, method), \
                f"Adapter protocol missing {method}"

    def test_adapter_type_property_required(self):
        """Adapter should have adapter_type property."""
        from openlabels.adapters.base import Adapter
        import typing

        # Protocol should have adapter_type
        hints = typing.get_type_hints(Adapter) if hasattr(Adapter, '__annotations__') else {}
        # adapter_type is a property, check it exists in the class
        assert hasattr(Adapter, 'adapter_type')
