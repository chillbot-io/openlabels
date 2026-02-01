"""
Tests for __main__.py module.

Tests the entry point for running as `python -m openlabels`.
"""

from unittest.mock import patch

import pytest


class TestMainModule:
    """Tests for __main__.py entry point."""

    def test_imports_main_from_cli(self):
        """Should import main function from cli.main."""
        from openlabels.__main__ import main
        assert callable(main)

    def test_main_is_cli_main(self):
        """Imported main should be the CLI main function."""
        from openlabels.__main__ import main
        from openlabels.cli.main import main as cli_main
        assert main is cli_main

    def test_module_can_be_imported(self):
        """Module should be importable without errors."""
        import openlabels.__main__
        assert hasattr(openlabels.__main__, 'main')
