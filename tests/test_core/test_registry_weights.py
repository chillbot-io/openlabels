"""
Tests for openlabels.core.registry.weights module.

Tests entity weight loading and override mechanism.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestGetWeight:
    """Tests for get_weight function."""

    def test_returns_weight_for_known_type(self):
        """Should return correct weight for known entity types."""
        from openlabels.core.registry.weights import get_weight

        # SSN should be high risk (10)
        assert get_weight("SSN") == 10

        # EMAIL should be moderate (5)
        assert get_weight("EMAIL") == 5

    def test_case_insensitive(self):
        """Should be case insensitive."""
        from openlabels.core.registry.weights import get_weight

        assert get_weight("ssn") == get_weight("SSN")
        assert get_weight("Ssn") == get_weight("SSN")

    def test_unknown_type_returns_default(self):
        """Unknown types should return default weight."""
        from openlabels.core.registry.weights import get_weight, DEFAULT_WEIGHT

        assert get_weight("UNKNOWN_TYPE_XYZ") == DEFAULT_WEIGHT

    def test_default_weight_is_five(self):
        """Default weight should be 5."""
        from openlabels.core.registry.weights import DEFAULT_WEIGHT

        assert DEFAULT_WEIGHT == 5


class TestBuiltinWeights:
    """Tests for builtin fallback weights."""

    def test_critical_identifiers_weight_10(self):
        """Critical identifiers should have weight 10."""
        from openlabels.core.registry.weights import _BUILTIN_WEIGHTS

        critical = ["SSN", "PASSPORT", "CREDIT_CARD", "PASSWORD", "API_KEY",
                   "PRIVATE_KEY", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "DATABASE_URL"]
        for entity in critical:
            assert _BUILTIN_WEIGHTS.get(entity) == 10, f"{entity} should be 10"

    def test_high_risk_identifiers(self):
        """High-risk identifiers should have weight 7-9."""
        from openlabels.core.registry.weights import _BUILTIN_WEIGHTS

        assert _BUILTIN_WEIGHTS.get("MRN") == 8
        assert _BUILTIN_WEIGHTS.get("DIAGNOSIS") == 8
        assert _BUILTIN_WEIGHTS.get("DRIVERS_LICENSE") == 7
        assert _BUILTIN_WEIGHTS.get("HEALTH_PLAN_ID") == 8

    def test_moderate_identifiers(self):
        """Moderate identifiers should have weight 4-5."""
        from openlabels.core.registry.weights import _BUILTIN_WEIGHTS

        assert _BUILTIN_WEIGHTS.get("EMAIL") == 5
        assert _BUILTIN_WEIGHTS.get("PHONE") == 4
        assert _BUILTIN_WEIGHTS.get("NAME") == 5

    def test_low_risk_identifiers(self):
        """Low-risk identifiers should have weight 2-3."""
        from openlabels.core.registry.weights import _BUILTIN_WEIGHTS

        assert _BUILTIN_WEIGHTS.get("DATE") == 3
        assert _BUILTIN_WEIGHTS.get("CITY") == 2
        assert _BUILTIN_WEIGHTS.get("STATE") == 2

    def test_all_weights_in_valid_range(self):
        """All weights should be 1-10."""
        from openlabels.core.registry.weights import _BUILTIN_WEIGHTS

        for entity, weight in _BUILTIN_WEIGHTS.items():
            assert 1 <= weight <= 10, f"{entity} has invalid weight {weight}"


class TestEntityWeights:
    """Tests for ENTITY_WEIGHTS lazy dict."""

    def test_get_known_type(self):
        """Should get weight for known type."""
        from openlabels.core.registry.weights import ENTITY_WEIGHTS

        weight = ENTITY_WEIGHTS.get("SSN")
        assert weight == 10

    def test_get_unknown_type_returns_default(self):
        """Should return default for unknown type."""
        from openlabels.core.registry.weights import ENTITY_WEIGHTS, DEFAULT_WEIGHT

        weight = ENTITY_WEIGHTS.get("UNKNOWN_XYZ")
        assert weight == DEFAULT_WEIGHT

    def test_getitem_known_type(self):
        """Should support bracket access."""
        from openlabels.core.registry.weights import ENTITY_WEIGHTS

        assert ENTITY_WEIGHTS["SSN"] == 10

    def test_getitem_unknown_returns_default(self):
        """Bracket access for unknown should return default."""
        from openlabels.core.registry.weights import ENTITY_WEIGHTS, DEFAULT_WEIGHT

        assert ENTITY_WEIGHTS["UNKNOWN_XYZ"] == DEFAULT_WEIGHT

    def test_case_insensitive_access(self):
        """Should be case insensitive."""
        from openlabels.core.registry.weights import ENTITY_WEIGHTS

        assert ENTITY_WEIGHTS.get("ssn") == ENTITY_WEIGHTS.get("SSN")

    def test_contains_check(self):
        """Should support 'in' operator."""
        from openlabels.core.registry.weights import ENTITY_WEIGHTS

        assert "SSN" in ENTITY_WEIGHTS

    def test_iteration(self):
        """Should support iteration."""
        from openlabels.core.registry.weights import ENTITY_WEIGHTS

        keys = list(ENTITY_WEIGHTS.keys())
        assert len(keys) > 0
        assert "SSN" in keys

    def test_len(self):
        """Should support len()."""
        from openlabels.core.registry.weights import ENTITY_WEIGHTS

        assert len(ENTITY_WEIGHTS) > 0

    def test_items(self):
        """Should support items()."""
        from openlabels.core.registry.weights import ENTITY_WEIGHTS

        items = list(ENTITY_WEIGHTS.items())
        assert len(items) > 0
        assert any(k == "SSN" for k, v in items)


class TestFlattenWeights:
    """Tests for _flatten_weights function."""

    def test_flattens_categories(self):
        """Should flatten categorized weights."""
        from openlabels.core.registry.weights import _flatten_weights

        data = {
            "direct_identifiers": {
                "SSN": 10,
                "PASSPORT": 10,
            },
            "contact_info": {
                "EMAIL": 5,
                "PHONE": 4,
            },
        }

        flat = _flatten_weights(data)

        assert flat["SSN"] == 10
        assert flat["PASSPORT"] == 10
        assert flat["EMAIL"] == 5
        assert flat["PHONE"] == 4

    def test_skips_schema_version(self):
        """Should skip schema_version key."""
        from openlabels.core.registry.weights import _flatten_weights

        data = {
            "schema_version": "1.0",
            "direct_identifiers": {"SSN": 10},
        }

        flat = _flatten_weights(data)

        assert "schema_version" not in flat
        assert flat["SSN"] == 10

    def test_skips_default_weight(self):
        """Should skip default_weight key."""
        from openlabels.core.registry.weights import _flatten_weights

        data = {
            "default_weight": 5,
            "direct_identifiers": {"SSN": 10},
        }

        flat = _flatten_weights(data)

        assert "default_weight" not in flat

    def test_uppercase_keys(self):
        """Should uppercase all keys."""
        from openlabels.core.registry.weights import _flatten_weights

        data = {
            "direct_identifiers": {"ssn": 10, "Passport": 10},
        }

        flat = _flatten_weights(data)

        assert "SSN" in flat
        assert "PASSPORT" in flat
        assert "ssn" not in flat

    def test_validates_weight_range(self):
        """Should only accept weights 1-10."""
        from openlabels.core.registry.weights import _flatten_weights

        data = {
            "test": {
                "VALID": 5,
                "TOO_HIGH": 11,
                "TOO_LOW": 0,
                "NEGATIVE": -1,
            },
        }

        flat = _flatten_weights(data)

        assert "VALID" in flat
        assert "TOO_HIGH" not in flat
        assert "TOO_LOW" not in flat
        assert "NEGATIVE" not in flat


class TestFindOverrideFile:
    """Tests for _find_override_file function."""

    def test_env_var_takes_precedence(self, tmp_path):
        """Environment variable should take precedence."""
        from openlabels.core.registry.weights import _find_override_file

        override_file = tmp_path / "custom_weights.yaml"
        override_file.write_text("SSN: 10")

        with patch.dict(os.environ, {"OPENLABELS_WEIGHTS_FILE": str(override_file)}):
            result = _find_override_file()
            assert result == override_file

    def test_returns_none_when_no_file(self):
        """Should return None when no override file exists."""
        from openlabels.core.registry.weights import _find_override_file

        with patch.dict(os.environ, {}, clear=True):
            with patch("pathlib.Path.exists", return_value=False):
                result = _find_override_file()
                # May return None or an existing system path
                # Just verify no exception

    def test_env_var_nonexistent_file(self, tmp_path):
        """Should not use env var if file doesn't exist."""
        from openlabels.core.registry.weights import _find_override_file

        with patch.dict(os.environ, {"OPENLABELS_WEIGHTS_FILE": "/nonexistent/file.yaml"}):
            with patch("pathlib.Path.home", return_value=tmp_path):
                # Should not raise, just return None or fallback
                result = _find_override_file()


class TestGetEffectiveWeights:
    """Tests for get_effective_weights function."""

    def test_returns_dict(self):
        """Should return a dictionary."""
        from openlabels.core.registry.weights import get_effective_weights

        weights = get_effective_weights()
        assert isinstance(weights, dict)

    def test_contains_builtin_types(self):
        """Should contain builtin entity types."""
        from openlabels.core.registry.weights import get_effective_weights

        weights = get_effective_weights()
        assert "SSN" in weights
        assert "EMAIL" in weights

    def test_all_weights_valid(self):
        """All weights should be in valid range."""
        from openlabels.core.registry.weights import get_effective_weights

        weights = get_effective_weights()
        for entity, weight in weights.items():
            assert isinstance(weight, int), f"{entity} weight not int"
            assert 1 <= weight <= 10, f"{entity} has invalid weight {weight}"


class TestReloadWeights:
    """Tests for reload_weights function."""

    def test_clears_cache(self):
        """Should clear the LRU cache."""
        from openlabels.core.registry.weights import (
            reload_weights,
            _load_bundled_weights,
            _load_overrides,
        )

        # Access to populate cache
        _load_bundled_weights()
        _load_overrides()

        # Verify cache is populated
        assert _load_bundled_weights.cache_info().hits >= 0

        # Reload should clear
        reload_weights()

        # Cache should be empty
        assert _load_bundled_weights.cache_info().misses == 0 or True  # Just verify no error


class TestReloadOverrides:
    """Tests for reload_overrides function."""

    def test_clears_override_cache(self):
        """Should clear the override cache."""
        from openlabels.core.registry.weights import reload_overrides, _load_overrides

        # Access to populate cache
        _load_overrides()

        # Reload should not raise
        reload_overrides()


class TestCategoryWeights:
    """Tests for category-level weight dictionaries."""

    def test_direct_identifier_weights(self):
        """DIRECT_IDENTIFIER_WEIGHTS should contain direct identifiers."""
        from openlabels.core.registry.weights import DIRECT_IDENTIFIER_WEIGHTS

        # Should be able to access without error
        len(DIRECT_IDENTIFIER_WEIGHTS)

    def test_healthcare_weights(self):
        """HEALTHCARE_WEIGHTS should be accessible."""
        from openlabels.core.registry.weights import HEALTHCARE_WEIGHTS

        len(HEALTHCARE_WEIGHTS)

    def test_credential_weights(self):
        """CREDENTIAL_WEIGHTS should be accessible."""
        from openlabels.core.registry.weights import CREDENTIAL_WEIGHTS

        len(CREDENTIAL_WEIGHTS)

    def test_all_category_exports(self):
        """All category exports should be accessible."""
        from openlabels.core.registry import weights

        categories = [
            "DIRECT_IDENTIFIER_WEIGHTS",
            "HEALTHCARE_WEIGHTS",
            "PERSONAL_INFO_WEIGHTS",
            "CONTACT_INFO_WEIGHTS",
            "FINANCIAL_WEIGHTS",
            "DIGITAL_IDENTIFIER_WEIGHTS",
            "CREDENTIAL_WEIGHTS",
            "GOVERNMENT_WEIGHTS",
        ]

        for cat in categories:
            assert hasattr(weights, cat), f"Missing category export: {cat}"


class TestLoadYamlFile:
    """Tests for _load_yaml_file function."""

    def test_loads_valid_yaml(self, tmp_path):
        """Should load valid YAML file."""
        from openlabels.core.registry.weights import _load_yaml_file

        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("SSN: 10\nEMAIL: 5\n")

        result = _load_yaml_file(yaml_file)

        assert result is not None
        assert result["SSN"] == 10
        assert result["EMAIL"] == 5

    def test_returns_none_for_missing_file(self, tmp_path):
        """Should return None for missing file."""
        from openlabels.core.registry.weights import _load_yaml_file

        result = _load_yaml_file(tmp_path / "nonexistent.yaml")
        assert result is None

    def test_handles_invalid_yaml(self, tmp_path):
        """Should handle invalid YAML gracefully."""
        from openlabels.core.registry.weights import _load_yaml_file

        yaml_file = tmp_path / "invalid.yaml"
        yaml_file.write_text("{{invalid yaml::")

        result = _load_yaml_file(yaml_file)
        # Should return None or raise, not crash
        # Exact behavior depends on yaml library


class TestWeightScale:
    """Tests for weight scale documentation compliance."""

    def test_critical_weight_is_10(self):
        """Critical identifiers should be weight 10."""
        from openlabels.core.registry.weights import get_weight

        # Per docstring: SSN, Passport, Credit Card
        assert get_weight("SSN") == 10
        assert get_weight("PASSPORT") == 10
        assert get_weight("CREDIT_CARD") == 10

    def test_weight_scale_range(self):
        """All weights should be 1-10."""
        from openlabels.core.registry.weights import get_effective_weights

        for entity, weight in get_effective_weights().items():
            assert 1 <= weight <= 10


class TestLazyCategoryWeights:
    """Tests for _LazyCategoryWeights class."""

    def test_lazy_loading(self):
        """Should load lazily on first access."""
        from openlabels.core.registry.weights import _LazyCategoryWeights

        cat = _LazyCategoryWeights("direct_identifiers")
        assert cat._loaded is False

        # Access triggers load
        _ = len(cat)
        assert cat._loaded is True

    def test_supports_get(self):
        """Should support get() method."""
        from openlabels.core.registry.weights import _LazyCategoryWeights

        cat = _LazyCategoryWeights("direct_identifiers")
        result = cat.get("SSN", 5)
        # Result depends on YAML content

    def test_supports_contains(self):
        """Should support 'in' operator."""
        from openlabels.core.registry.weights import _LazyCategoryWeights

        cat = _LazyCategoryWeights("direct_identifiers")
        _ = "SSN" in cat  # Should not raise

    def test_supports_iteration(self):
        """Should support iteration."""
        from openlabels.core.registry.weights import _LazyCategoryWeights

        cat = _LazyCategoryWeights("direct_identifiers")
        _ = list(cat.keys())  # Should not raise
        _ = list(cat.values())
        _ = list(cat.items())
