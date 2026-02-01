"""Tests for configuration provider service.

Tests ConfigProvider: settings management, validation, runtime updates.
"""

import pytest
import threading
import time
from unittest.mock import MagicMock

from scrubiq.config import Config
from scrubiq.services.config_provider import (
    ConfigProvider,
    SettingCategory,
    SettingMetadata,
    SETTINGS_REGISTRY,
    _register_setting,
    _KEY_TO_ATTR,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def config():
    """Create a default Config instance."""
    return Config()


@pytest.fixture
def provider(config):
    """Create a ConfigProvider with default config."""
    return ConfigProvider(config)


# =============================================================================
# SETTING CATEGORY TESTS
# =============================================================================

class TestSettingCategory:
    """Tests for SettingCategory enum."""

    def test_all_categories_defined(self):
        """All expected categories are defined."""
        expected = {
            "security", "detection", "pipeline", "api",
            "storage", "llm", "files", "rate_limits"
        }
        actual = {c.value for c in SettingCategory}
        assert expected == actual

    def test_category_is_string_enum(self):
        """Categories can be used as strings."""
        assert SettingCategory.SECURITY == "security"
        assert SettingCategory.DETECTION == "detection"


# =============================================================================
# SETTING METADATA TESTS
# =============================================================================

class TestSettingMetadata:
    """Tests for SettingMetadata dataclass."""

    def test_create_metadata(self):
        """Can create SettingMetadata."""
        meta = SettingMetadata(
            key="test.setting",
            category=SettingCategory.DETECTION,
            description="Test setting",
            value_type="float",
            default=0.5,
        )

        assert meta.key == "test.setting"
        assert meta.category == SettingCategory.DETECTION
        assert meta.value_type == "float"
        assert meta.default == 0.5

    def test_metadata_optional_fields(self):
        """Optional fields have correct defaults."""
        meta = SettingMetadata(
            key="test.setting",
            category=SettingCategory.DETECTION,
            description="Test",
            value_type="int",
            default=10,
        )

        assert meta.current is None
        assert meta.allowed_values is None
        assert meta.min_value is None
        assert meta.max_value is None
        assert meta.requires_restart is False
        assert meta.runtime_editable is True
        assert meta.sensitive is False


# =============================================================================
# SETTINGS REGISTRY TESTS
# =============================================================================

class TestSettingsRegistry:
    """Tests for global settings registry."""

    def test_registry_not_empty(self):
        """Registry contains settings."""
        assert len(SETTINGS_REGISTRY) > 0

    def test_all_keys_have_metadata(self):
        """All registered keys have valid metadata."""
        for key, meta in SETTINGS_REGISTRY.items():
            assert isinstance(meta, SettingMetadata)
            assert meta.key == key
            assert isinstance(meta.category, SettingCategory)

    def test_detection_settings_registered(self):
        """Detection settings are registered."""
        assert "detection.min_confidence" in SETTINGS_REGISTRY
        assert "detection.review_threshold" in SETTINGS_REGISTRY

    def test_pipeline_settings_registered(self):
        """Pipeline settings are registered."""
        assert "pipeline.coref_enabled" in SETTINGS_REGISTRY
        assert "pipeline.safe_harbor_enabled" in SETTINGS_REGISTRY

    def test_security_settings_registered(self):
        """Security settings are registered."""
        assert "security.session_timeout_minutes" in SETTINGS_REGISTRY
        assert "security.encryption_enabled" in SETTINGS_REGISTRY

    def test_key_to_attr_mapping_exists(self):
        """All registry keys have attr mappings."""
        for key in SETTINGS_REGISTRY:
            assert key in _KEY_TO_ATTR


# =============================================================================
# CONFIG PROVIDER BASIC TESTS
# =============================================================================

class TestConfigProviderBasic:
    """Basic tests for ConfigProvider."""

    def test_create_provider(self, config):
        """Can create ConfigProvider."""
        provider = ConfigProvider(config)
        assert provider is not None
        assert provider.config is config

    def test_get_categories(self, provider):
        """get_categories returns all categories."""
        categories = provider.get_categories()

        assert "security" in categories
        assert "detection" in categories
        assert "pipeline" in categories


# =============================================================================
# CONFIG PROVIDER GET TESTS
# =============================================================================

class TestConfigProviderGet:
    """Tests for ConfigProvider.get method."""

    def test_get_existing_setting(self, provider):
        """get() returns value for existing setting."""
        value = provider.get("detection.min_confidence")

        assert isinstance(value, float)
        assert 0.0 <= value <= 1.0

    def test_get_unknown_key_raises(self, provider):
        """get() raises KeyError for unknown key."""
        with pytest.raises(KeyError) as exc:
            provider.get("unknown.setting")

        assert "unknown.setting" in str(exc.value)

    def test_get_bool_setting(self, provider):
        """get() returns bool settings."""
        value = provider.get("pipeline.coref_enabled")

        assert isinstance(value, bool)

    def test_get_int_setting(self, provider):
        """get() returns int settings."""
        value = provider.get("api.port")

        assert isinstance(value, int)

    def test_get_string_setting(self, provider):
        """get() returns string settings."""
        value = provider.get("api.host")

        assert isinstance(value, str)


# =============================================================================
# CONFIG PROVIDER SET TESTS
# =============================================================================

class TestConfigProviderSet:
    """Tests for ConfigProvider.set method."""

    def test_set_float_value(self, provider):
        """set() updates float value."""
        original = provider.get("detection.min_confidence")

        provider.set("detection.min_confidence", 0.75)

        assert provider.get("detection.min_confidence") == 0.75

    def test_set_bool_value(self, provider):
        """set() updates bool value."""
        provider.set("pipeline.coref_enabled", False)

        assert provider.get("pipeline.coref_enabled") is False

    def test_set_int_value(self, provider):
        """set() updates int value."""
        provider.set("pipeline.coref_window_sentences", 5)

        assert provider.get("pipeline.coref_window_sentences") == 5

    def test_set_unknown_key_raises(self, provider):
        """set() raises KeyError for unknown key."""
        with pytest.raises(KeyError):
            provider.set("unknown.setting", "value")

    def test_set_non_editable_raises(self, provider):
        """set() raises RuntimeError for non-editable settings."""
        # encryption_enabled is not runtime editable
        with pytest.raises(RuntimeError) as exc:
            provider.set("security.encryption_enabled", False)

        assert "cannot be changed at runtime" in str(exc.value)


# =============================================================================
# CONFIG PROVIDER VALIDATION TESTS
# =============================================================================

class TestConfigProviderValidation:
    """Tests for value validation."""

    def test_validate_int_type(self, provider):
        """Rejects wrong type for int setting."""
        with pytest.raises(ValueError) as exc:
            provider.set("api.port", "not an int")

        assert "Expected int" in str(exc.value)

    def test_validate_float_type(self, provider):
        """Rejects wrong type for float setting."""
        with pytest.raises(ValueError) as exc:
            provider.set("detection.min_confidence", "not a float")

        assert "Expected float" in str(exc.value)

    def test_validate_bool_type(self, provider):
        """Rejects wrong type for bool setting."""
        with pytest.raises(ValueError) as exc:
            provider.set("pipeline.coref_enabled", "true")

        assert "Expected bool" in str(exc.value)

    def test_validate_min_value(self, provider):
        """Rejects value below minimum."""
        with pytest.raises(ValueError) as exc:
            provider.set("detection.min_confidence", -0.5)

        assert "below minimum" in str(exc.value)

    def test_validate_max_value(self, provider):
        """Rejects value above maximum."""
        with pytest.raises(ValueError) as exc:
            provider.set("detection.min_confidence", 1.5)

        assert "above maximum" in str(exc.value)

    def test_validate_allowed_values(self, provider):
        """Rejects value not in allowed list."""
        with pytest.raises(ValueError) as exc:
            provider.set("files.face_redaction_method", "invalid")

        assert "Invalid value" in str(exc.value)
        assert "Allowed:" in str(exc.value)

    def test_validate_float_accepts_int(self, provider):
        """Float settings accept int values."""
        provider.set("detection.min_confidence", 0)

        assert provider.get("detection.min_confidence") == 0.0


# =============================================================================
# CONFIG PROVIDER METADATA TESTS
# =============================================================================

class TestConfigProviderMetadata:
    """Tests for metadata retrieval."""

    def test_get_metadata_returns_metadata(self, provider):
        """get_metadata returns SettingMetadata."""
        meta = provider.get_metadata("detection.min_confidence")

        assert isinstance(meta, SettingMetadata)
        assert meta.key == "detection.min_confidence"
        assert meta.category == SettingCategory.DETECTION

    def test_get_metadata_includes_current(self, provider):
        """get_metadata includes current value."""
        provider.set("detection.min_confidence", 0.8)
        meta = provider.get_metadata("detection.min_confidence")

        assert meta.current == 0.8

    def test_get_metadata_unknown_returns_none(self, provider):
        """get_metadata returns None for unknown key."""
        result = provider.get_metadata("unknown.setting")

        assert result is None

    def test_get_all_with_metadata(self, provider):
        """get_all_with_metadata returns all settings."""
        result = provider.get_all_with_metadata()

        assert isinstance(result, dict)
        assert len(result) == len(SETTINGS_REGISTRY)

        for key, data in result.items():
            assert "key" in data
            assert "category" in data
            assert "description" in data
            assert "type" in data
            assert "current" in data

    def test_sensitive_values_hidden_in_metadata(self, provider):
        """Sensitive values are hidden in get_all_with_metadata."""
        result = provider.get_all_with_metadata()

        # Check that sensitive settings show "***"
        for key, data in result.items():
            meta = SETTINGS_REGISTRY[key]
            if meta.sensitive:
                assert data["current"] == "***"


# =============================================================================
# CONFIG PROVIDER GET ALL TESTS
# =============================================================================

class TestConfigProviderGetAll:
    """Tests for get_all and get_by_category."""

    def test_get_all_returns_dict(self, provider):
        """get_all returns all settings."""
        result = provider.get_all()

        assert isinstance(result, dict)
        assert len(result) == len(SETTINGS_REGISTRY)

    def test_get_by_category(self, provider):
        """get_by_category filters by category."""
        result = provider.get_by_category(SettingCategory.DETECTION)

        assert "detection.min_confidence" in result
        assert "detection.review_threshold" in result
        assert "api.port" not in result

    def test_get_by_category_pipeline(self, provider):
        """get_by_category returns pipeline settings."""
        result = provider.get_by_category(SettingCategory.PIPELINE)

        assert "pipeline.coref_enabled" in result
        assert "detection.min_confidence" not in result


# =============================================================================
# CONFIG PROVIDER CHANGE CALLBACKS TESTS
# =============================================================================

class TestConfigProviderCallbacks:
    """Tests for change callbacks."""

    def test_on_change_registers_callback(self, provider):
        """on_change registers a callback."""
        callback = MagicMock()

        provider.on_change(callback)

        # Verify callback is called on change
        provider.set("detection.min_confidence", 0.7)

        callback.assert_called_once()
        args = callback.call_args[0]
        assert args[0] == "detection.min_confidence"
        assert args[2] == 0.7  # new value

    def test_callback_receives_old_and_new_value(self, provider):
        """Callback receives old and new values."""
        old_value = provider.get("detection.min_confidence")
        callback = MagicMock()
        provider.on_change(callback)

        provider.set("detection.min_confidence", 0.9)

        args = callback.call_args[0]
        assert args[1] == old_value  # old value
        assert args[2] == 0.9  # new value

    def test_multiple_callbacks(self, provider):
        """Multiple callbacks are all called."""
        callback1 = MagicMock()
        callback2 = MagicMock()

        provider.on_change(callback1)
        provider.on_change(callback2)

        provider.set("detection.min_confidence", 0.6)

        callback1.assert_called_once()
        callback2.assert_called_once()

    def test_callback_exception_does_not_break_set(self, provider):
        """Callback exception doesn't prevent set."""
        def failing_callback(key, old, new):
            raise Exception("Callback failed")

        provider.on_change(failing_callback)

        # Should not raise
        provider.set("detection.min_confidence", 0.8)

        # Value should still be updated
        assert provider.get("detection.min_confidence") == 0.8


# =============================================================================
# CONFIG PROVIDER EXPORT/IMPORT TESTS
# =============================================================================

class TestConfigProviderExportImport:
    """Tests for export and import."""

    def test_export_to_dict(self, provider):
        """export_to_dict returns serializable dict."""
        result = provider.export_to_dict()

        assert isinstance(result, dict)
        # Should exclude sensitive settings by default
        for key in result:
            meta = SETTINGS_REGISTRY.get(key)
            if meta:
                assert not meta.sensitive

    def test_export_excludes_sensitive_patterns(self, provider):
        """export_to_dict excludes sensitive patterns."""
        result = provider.export_to_dict()

        # Should not include gateway_url, ollama_url, etc.
        for key in result:
            assert "gateway_url" not in key
            assert "ollama_url" not in key

    def test_export_include_sensitive(self, provider):
        """export_to_dict can include sensitive when requested."""
        result = provider.export_to_dict(include_sensitive=True)

        # Should include all settings
        assert len(result) == len(SETTINGS_REGISTRY)

    def test_import_from_dict(self, provider):
        """import_from_dict updates settings."""
        data = {
            "detection.min_confidence": 0.65,
            "pipeline.coref_enabled": False,
        }

        updated = provider.import_from_dict(data)

        assert "detection.min_confidence" in updated
        assert "pipeline.coref_enabled" in updated
        assert provider.get("detection.min_confidence") == 0.65
        assert provider.get("pipeline.coref_enabled") is False

    def test_import_ignores_unknown_keys(self, provider):
        """import_from_dict ignores unknown keys."""
        data = {
            "unknown.setting": "value",
            "detection.min_confidence": 0.7,
        }

        updated = provider.import_from_dict(data)

        assert "detection.min_confidence" in updated
        assert "unknown.setting" not in updated

    def test_import_skips_invalid_values(self, provider):
        """import_from_dict skips invalid values."""
        original = provider.get("detection.min_confidence")
        data = {
            "detection.min_confidence": "invalid",
        }

        updated = provider.import_from_dict(data)

        assert "detection.min_confidence" not in updated
        assert provider.get("detection.min_confidence") == original


# =============================================================================
# THREAD SAFETY TESTS
# =============================================================================

class TestConfigProviderThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_reads(self, provider):
        """Concurrent reads don't cause issues."""
        results = []
        errors = []

        def reader():
            try:
                for _ in range(100):
                    value = provider.get("detection.min_confidence")
                    results.append(value)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 1000

    def test_concurrent_writes(self, provider):
        """Concurrent writes don't cause issues."""
        errors = []

        def writer(value):
            try:
                for _ in range(50):
                    provider.set("detection.min_confidence", value)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer, args=(0.5 + i * 0.01,))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # Value should be one of the valid values
        value = provider.get("detection.min_confidence")
        assert 0.5 <= value <= 0.6

    def test_concurrent_callbacks(self, provider):
        """Callbacks are thread-safe."""
        callback_count = [0]
        lock = threading.Lock()

        def callback(key, old, new):
            with lock:
                callback_count[0] += 1

        provider.on_change(callback)

        def writer():
            for i in range(20):
                provider.set("detection.min_confidence", 0.5 + i * 0.01)

        threads = [threading.Thread(target=writer) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All callbacks should have been called
        assert callback_count[0] == 100


# =============================================================================
# REQUIRES RESTART TESTS
# =============================================================================

class TestRequiresRestart:
    """Tests for requires_restart flag."""

    def test_restart_required_settings(self):
        """Some settings require restart."""
        restart_keys = [
            key for key, meta in SETTINGS_REGISTRY.items()
            if meta.requires_restart
        ]

        assert len(restart_keys) > 0
        assert "api.host" in restart_keys
        assert "api.port" in restart_keys

    def test_restart_not_required_settings(self):
        """Most settings don't require restart."""
        no_restart_keys = [
            key for key, meta in SETTINGS_REGISTRY.items()
            if not meta.requires_restart
        ]

        assert len(no_restart_keys) > 0
        assert "detection.min_confidence" in no_restart_keys
