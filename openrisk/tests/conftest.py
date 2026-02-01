"""Pytest configuration and fixtures.

Handles optional dependencies gracefully (Qt, extractors, etc.)
"""
import sys
import pytest

# Check if Qt is available BEFORE pytest-qt tries to load it
_qt_available = False
_qt_skip_reason = "Qt not available"

try:
    # Try importing PySide6 directly to check availability
    from PySide6 import QtWidgets
    _qt_available = True
except ImportError as e:
    _qt_skip_reason = f"PySide6 not installed: {e}"
except OSError as e:
    # This catches missing system libraries like libEGL.so.1
    _qt_skip_reason = f"Qt system libraries missing: {e}"


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "gui: mark test as requiring Qt GUI (deselected by default on headless systems)"
    )


def pytest_collection_modifyitems(config, items):
    """Skip GUI tests if Qt is not available."""
    if _qt_available:
        return

    skip_qt = pytest.mark.skip(reason=_qt_skip_reason)
    for item in items:
        # Skip any test in test_gui.py or marked with @pytest.mark.gui
        if "test_gui" in item.nodeid or "gui" in item.keywords:
            item.add_marker(skip_qt)


# Only expose qtbot fixture if Qt is available
if _qt_available:
    # pytest-qt will provide qtbot automatically
    pass
else:
    # Provide a dummy qtbot that skips tests
    @pytest.fixture
    def qtbot():
        pytest.skip(_qt_skip_reason)
