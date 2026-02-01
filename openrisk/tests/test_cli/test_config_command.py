"""
Tests for the config CLI command.

Tests configuration loading, saving, and manipulation functions.
"""

import json
import argparse
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from openlabels.cli.commands.config import (
    DEFAULT_CONFIG,
    get_config_path,
    load_config,
    save_config,
    deep_merge,
    get_nested_value,
    set_nested_value,
    cmd_config,
    add_config_parser,
)


class TestDefaultConfig:
    """Tests for default configuration structure."""

    def test_default_config_has_scanning(self):
        """Default config should have scanning section."""
        assert "scanning" in DEFAULT_CONFIG
        assert "max_file_size_mb" in DEFAULT_CONFIG["scanning"]
        assert "threads" in DEFAULT_CONFIG["scanning"]

    def test_default_config_has_storage(self):
        """Default config should have storage section."""
        assert "storage" in DEFAULT_CONFIG
        assert "quarantine_path" in DEFAULT_CONFIG["storage"]
        assert "index_backend" in DEFAULT_CONFIG["storage"]

    def test_default_config_has_display(self):
        """Default config should have display section."""
        assert "display" in DEFAULT_CONFIG
        assert "show_hidden_files" in DEFAULT_CONFIG["display"]
        assert "max_results" in DEFAULT_CONFIG["display"]

    def test_default_threads_is_positive(self):
        """Default threads should be positive."""
        assert DEFAULT_CONFIG["scanning"]["threads"] > 0

    def test_default_max_file_size_is_reasonable(self):
        """Default max file size should be reasonable."""
        assert 1 <= DEFAULT_CONFIG["scanning"]["max_file_size_mb"] <= 1000


class TestGetConfigPath:
    """Tests for get_config_path function."""

    def test_returns_path(self):
        """Should return a Path object."""
        result = get_config_path()
        assert isinstance(result, Path)

    def test_path_ends_with_config_json(self):
        """Config path should end with config.json."""
        result = get_config_path()
        assert result.name == "config.json"

    def test_path_is_in_openlabels_dir(self):
        """Config should be in .openlabels directory."""
        result = get_config_path()
        assert ".openlabels" in str(result)


class TestLoadConfig:
    """Tests for load_config function."""

    def test_returns_dict(self):
        """Should return a dictionary."""
        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = Path("/nonexistent/config.json")
            result = load_config()
            assert isinstance(result, dict)

    def test_returns_default_when_file_missing(self):
        """Should return defaults when config file doesn't exist."""
        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = Path("/nonexistent/config.json")
            result = load_config()
            assert result == DEFAULT_CONFIG

    def test_loads_from_file(self, tmp_path):
        """Should load config from file."""
        config_file = tmp_path / "config.json"
        custom_config = {"scanning": {"threads": 16}}
        config_file.write_text(json.dumps(custom_config))

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            result = load_config()
            assert result["scanning"]["threads"] == 16

    def test_merges_with_defaults(self, tmp_path):
        """Should merge loaded config with defaults."""
        config_file = tmp_path / "config.json"
        # Only override one value
        custom_config = {"scanning": {"threads": 16}}
        config_file.write_text(json.dumps(custom_config))

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            result = load_config()
            # Custom value preserved
            assert result["scanning"]["threads"] == 16
            # Default values still present
            assert "max_file_size_mb" in result["scanning"]
            assert "storage" in result

    def test_handles_invalid_json(self, tmp_path):
        """Should handle invalid JSON gracefully."""
        config_file = tmp_path / "config.json"
        config_file.write_text("not valid json {{{")

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            result = load_config()
            # Should return defaults on error
            assert result == DEFAULT_CONFIG


class TestSaveConfig:
    """Tests for save_config function."""

    def test_saves_to_file(self, tmp_path):
        """Should save config to file."""
        config_file = tmp_path / ".openlabels" / "config.json"

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            result = save_config({"test": "value"})

        assert result is True
        assert config_file.exists()
        saved = json.loads(config_file.read_text())
        assert saved["test"] == "value"

    def test_creates_parent_directories(self, tmp_path):
        """Should create parent directories if needed."""
        config_file = tmp_path / "deep" / "nested" / "config.json"

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            result = save_config({"key": "value"})

        assert result is True
        assert config_file.exists()

    def test_returns_false_on_error(self, tmp_path):
        """Should return False on write error."""
        config_file = tmp_path / "config.json"

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            # Mock open to raise IOError
            with patch("builtins.open", side_effect=IOError("Permission denied")):
                result = save_config({"key": "value"})
                assert result is False


class TestDeepMerge:
    """Tests for deep_merge function."""

    def test_merges_flat_dicts(self):
        """Should merge flat dictionaries."""
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        deep_merge(base, override)
        assert base == {"a": 1, "b": 3, "c": 4}

    def test_merges_nested_dicts(self):
        """Should merge nested dictionaries recursively."""
        base = {"outer": {"inner1": 1, "inner2": 2}}
        override = {"outer": {"inner2": 20, "inner3": 30}}
        deep_merge(base, override)
        assert base["outer"]["inner1"] == 1
        assert base["outer"]["inner2"] == 20
        assert base["outer"]["inner3"] == 30

    def test_override_replaces_non_dict(self):
        """Should replace non-dict values entirely."""
        base = {"key": [1, 2, 3]}
        override = {"key": [4, 5]}
        deep_merge(base, override)
        assert base["key"] == [4, 5]

    def test_adds_new_keys(self):
        """Should add keys that don't exist in base."""
        base = {"existing": 1}
        override = {"new": 2}
        deep_merge(base, override)
        assert base["existing"] == 1
        assert base["new"] == 2

    def test_empty_override_no_change(self):
        """Empty override should not change base."""
        base = {"a": 1}
        deep_merge(base, {})
        assert base == {"a": 1}


class TestGetNestedValue:
    """Tests for get_nested_value function."""

    def test_gets_top_level_value(self):
        """Should get top-level values."""
        config = {"key": "value"}
        result = get_nested_value(config, "key")
        assert result == "value"

    def test_gets_nested_value(self):
        """Should get nested values with dot notation."""
        config = {"outer": {"inner": "value"}}
        result = get_nested_value(config, "outer.inner")
        assert result == "value"

    def test_gets_deeply_nested_value(self):
        """Should get deeply nested values."""
        config = {"a": {"b": {"c": {"d": "deep"}}}}
        result = get_nested_value(config, "a.b.c.d")
        assert result == "deep"

    def test_returns_none_for_missing_key(self):
        """Should return None for missing keys."""
        config = {"existing": "value"}
        result = get_nested_value(config, "missing")
        assert result is None

    def test_returns_none_for_missing_nested_key(self):
        """Should return None for missing nested keys."""
        config = {"outer": {"inner": "value"}}
        result = get_nested_value(config, "outer.nonexistent")
        assert result is None

    def test_returns_none_when_path_traverses_non_dict(self):
        """Should return None when path goes through non-dict."""
        config = {"key": "string_value"}
        result = get_nested_value(config, "key.nested")
        assert result is None


class TestSetNestedValue:
    """Tests for set_nested_value function."""

    def test_sets_top_level_value(self):
        """Should set top-level values."""
        config = {}
        result = set_nested_value(config, "key", "value")
        assert result is True
        assert config["key"] == "value"

    def test_sets_nested_value(self):
        """Should set nested values."""
        config = {"outer": {}}
        result = set_nested_value(config, "outer.inner", "value")
        assert result is True
        assert config["outer"]["inner"] == "value"

    def test_creates_intermediate_dicts(self):
        """Should create intermediate dictionaries."""
        config = {}
        result = set_nested_value(config, "a.b.c", "value")
        assert result is True
        assert config["a"]["b"]["c"] == "value"

    def test_converts_to_bool_true(self):
        """Should convert string to bool when existing value is bool."""
        config = {"flag": False}
        set_nested_value(config, "flag", "true")
        assert config["flag"] is True

    def test_converts_to_bool_false(self):
        """Should convert 'false' to False."""
        config = {"flag": True}
        set_nested_value(config, "flag", "false")
        assert config["flag"] is False

    def test_converts_to_bool_yes(self):
        """Should convert 'yes' to True."""
        config = {"flag": False}
        set_nested_value(config, "flag", "yes")
        assert config["flag"] is True

    def test_converts_to_int(self):
        """Should convert string to int when existing value is int."""
        config = {"count": 0}
        result = set_nested_value(config, "count", "42")
        assert result is True
        assert config["count"] == 42

    def test_returns_false_for_invalid_int(self):
        """Should return False when int conversion fails."""
        config = {"count": 0}
        result = set_nested_value(config, "count", "not_a_number")
        assert result is False

    def test_converts_to_float(self):
        """Should convert string to float when existing value is float."""
        config = {"ratio": 0.0}
        result = set_nested_value(config, "ratio", "3.14")
        assert result is True
        assert config["ratio"] == 3.14

    def test_returns_false_for_invalid_float(self):
        """Should return False when float conversion fails."""
        config = {"ratio": 0.0}
        result = set_nested_value(config, "ratio", "not_a_float")
        assert result is False

    def test_converts_to_list(self):
        """Should convert comma-separated string to list."""
        config = {"items": []}
        set_nested_value(config, "items", "a, b, c")
        assert config["items"] == ["a", "b", "c"]


class TestCmdConfig:
    """Tests for cmd_config command handler."""

    @pytest.fixture
    def mock_args(self):
        """Create mock args object."""
        args = MagicMock()
        args.show = False
        args.get = None
        args.set = None
        args.reset = False
        return args

    def test_show_returns_zero(self, mock_args, tmp_path):
        """--show should return 0."""
        mock_args.show = True
        config_file = tmp_path / "config.json"

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            with patch("openlabels.cli.commands.config.config_tree"):
                with patch("openlabels.cli.commands.config.echo"):
                    result = cmd_config(mock_args)

        assert result == 0

    def test_get_existing_key(self, mock_args, tmp_path):
        """--get should return value for existing key."""
        mock_args.get = "scanning.threads"
        config_file = tmp_path / "config.json"

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            with patch("openlabels.cli.commands.config.echo") as mock_echo:
                result = cmd_config(mock_args)

        assert result == 0
        # Should have echoed the value
        mock_echo.assert_called()

    def test_get_missing_key_returns_error(self, mock_args, tmp_path):
        """--get with missing key should return 1."""
        mock_args.get = "nonexistent.key"
        config_file = tmp_path / "config.json"

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            with patch("openlabels.cli.commands.config.error"):
                result = cmd_config(mock_args)

        assert result == 1

    def test_set_requires_two_args(self, mock_args, tmp_path):
        """--set with wrong number of args should return 1."""
        mock_args.set = ["only_one"]
        config_file = tmp_path / "config.json"

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            with patch("openlabels.cli.commands.config.error"):
                result = cmd_config(mock_args)

        assert result == 1

    def test_set_valid_value(self, mock_args, tmp_path):
        """--set with valid key/value should succeed."""
        mock_args.set = ["scanning.threads", "8"]
        config_file = tmp_path / ".openlabels" / "config.json"

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            with patch("openlabels.cli.commands.config.success"):
                result = cmd_config(mock_args)

        assert result == 0
        # Verify it was saved
        saved = json.loads(config_file.read_text())
        assert saved["scanning"]["threads"] == 8

    def test_reset_restores_defaults(self, mock_args, tmp_path):
        """--reset should restore default configuration."""
        mock_args.reset = True
        config_file = tmp_path / ".openlabels" / "config.json"

        # Create non-default config first
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(json.dumps({"custom": "value"}))

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            with patch("openlabels.cli.commands.config.success"):
                result = cmd_config(mock_args)

        assert result == 0
        # Verify defaults were saved
        saved = json.loads(config_file.read_text())
        assert saved == DEFAULT_CONFIG

    def test_default_shows_help(self, mock_args, tmp_path):
        """No args should show help and return 0."""
        config_file = tmp_path / "config.json"

        with patch("openlabels.cli.commands.config.get_config_path") as mock_path:
            mock_path.return_value = config_file
            with patch("openlabels.cli.commands.config.config_tree"):
                with patch("openlabels.cli.commands.config.echo") as mock_echo:
                    result = cmd_config(mock_args)

        assert result == 0
        # Should show commands help
        assert mock_echo.call_count >= 4


class TestAddConfigParser:
    """Tests for add_config_parser function."""

    def test_adds_parser(self):
        """Should add config parser to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        result = add_config_parser(subparsers)

        assert result is not None

    def test_parser_has_show_arg(self):
        """Parser should have --show argument."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_config_parser(subparsers)

        args = parser.parse_args(["config", "--show"])
        assert args.show is True

    def test_parser_has_get_arg(self):
        """Parser should have --get argument."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_config_parser(subparsers)

        args = parser.parse_args(["config", "--get", "some.key"])
        assert args.get == "some.key"

    def test_parser_has_set_arg(self):
        """Parser should have --set argument with two values."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_config_parser(subparsers)

        args = parser.parse_args(["config", "--set", "key", "value"])
        assert args.set == ["key", "value"]

    def test_parser_has_reset_arg(self):
        """Parser should have --reset argument."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_config_parser(subparsers)

        args = parser.parse_args(["config", "--reset"])
        assert args.reset is True

    def test_hidden_mode_suppresses_help(self):
        """hidden=True should suppress help text."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        # Just verify it doesn't raise
        result = add_config_parser(subparsers, hidden=True)
        assert result is not None
