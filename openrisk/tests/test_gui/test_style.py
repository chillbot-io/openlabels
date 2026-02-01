"""
Tests for GUI style module.

Tests brand colors, stylesheet generation, and tier color lookup.
"""

import pytest

from openlabels.gui.style import COLORS, get_stylesheet, get_tier_color


class TestColors:
    """Tests for COLORS dictionary."""

    def test_colors_is_dict(self):
        """COLORS should be a dictionary."""
        assert isinstance(COLORS, dict)

    def test_has_primary_colors(self):
        """Should have primary brand colors."""
        assert "primary" in COLORS
        assert "primary_dark" in COLORS
        assert "primary_light" in COLORS

    def test_has_status_colors(self):
        """Should have status indicator colors."""
        assert "success" in COLORS
        assert "warning" in COLORS
        assert "danger" in COLORS

    def test_has_background_colors(self):
        """Should have background colors."""
        assert "bg" in COLORS
        assert "bg_secondary" in COLORS
        assert "bg_tertiary" in COLORS

    def test_has_text_colors(self):
        """Should have text colors."""
        assert "text" in COLORS
        assert "text_secondary" in COLORS
        assert "text_muted" in COLORS

    def test_has_border_colors(self):
        """Should have border colors."""
        assert "border" in COLORS
        assert "border_focus" in COLORS

    def test_has_tier_colors(self):
        """Should have risk tier colors."""
        assert "tier_critical" in COLORS
        assert "tier_high" in COLORS
        assert "tier_medium" in COLORS
        assert "tier_low" in COLORS
        assert "tier_minimal" in COLORS

    def test_colors_are_hex(self):
        """All colors should be hex format."""
        for name, color in COLORS.items():
            assert isinstance(color, str), f"{name} is not a string"
            assert color.startswith("#"), f"{name} doesn't start with #"
            assert len(color) == 7, f"{name} is not 7 chars (e.g., #RRGGBB)"

    def test_primary_is_blue(self):
        """Primary color should be blue."""
        # Blue colors typically have high blue component
        primary = COLORS["primary"]
        # #2563eb - blue value (eb = 235) > red value (25 = 37)
        assert primary.lower() == "#2563eb"


class TestGetStylesheet:
    """Tests for get_stylesheet function."""

    def test_returns_string(self):
        """Should return a string."""
        result = get_stylesheet()
        assert isinstance(result, str)

    def test_stylesheet_not_empty(self):
        """Stylesheet should not be empty."""
        result = get_stylesheet()
        assert len(result) > 0

    def test_contains_qwidget_rules(self):
        """Should contain QWidget rules."""
        result = get_stylesheet()
        assert "QWidget" in result

    def test_contains_qpushbutton_rules(self):
        """Should contain QPushButton rules."""
        result = get_stylesheet()
        assert "QPushButton" in result

    def test_contains_qtablewidget_rules(self):
        """Should contain QTableWidget rules."""
        result = get_stylesheet()
        assert "QTableWidget" in result

    def test_contains_color_references(self):
        """Should reference colors from COLORS dict."""
        result = get_stylesheet()
        # Should contain the primary color
        assert COLORS["primary"] in result

    def test_contains_hover_states(self):
        """Should contain hover state rules."""
        result = get_stylesheet()
        assert ":hover" in result

    def test_contains_disabled_states(self):
        """Should contain disabled state rules."""
        result = get_stylesheet()
        assert ":disabled" in result

    def test_contains_border_radius(self):
        """Should use border-radius for rounded corners."""
        result = get_stylesheet()
        assert "border-radius" in result

    def test_contains_font_family(self):
        """Should specify font family."""
        result = get_stylesheet()
        assert "font-family" in result


class TestGetTierColor:
    """Tests for get_tier_color function."""

    def test_critical_tier(self):
        """CRITICAL should return critical color."""
        result = get_tier_color("CRITICAL")
        assert result == COLORS["tier_critical"]

    def test_high_tier(self):
        """HIGH should return high color."""
        result = get_tier_color("HIGH")
        assert result == COLORS["tier_high"]

    def test_medium_tier(self):
        """MEDIUM should return medium color."""
        result = get_tier_color("MEDIUM")
        assert result == COLORS["tier_medium"]

    def test_low_tier(self):
        """LOW should return low color."""
        result = get_tier_color("LOW")
        assert result == COLORS["tier_low"]

    def test_minimal_tier(self):
        """MINIMAL should return minimal color."""
        result = get_tier_color("MINIMAL")
        assert result == COLORS["tier_minimal"]

    def test_unknown_tier(self):
        """UNKNOWN should return muted color."""
        result = get_tier_color("UNKNOWN")
        assert result == COLORS["text_muted"]

    def test_case_insensitive(self):
        """Should be case insensitive."""
        assert get_tier_color("critical") == COLORS["tier_critical"]
        assert get_tier_color("Critical") == COLORS["tier_critical"]
        assert get_tier_color("CRITICAL") == COLORS["tier_critical"]

    def test_invalid_tier_returns_muted(self):
        """Invalid tier should return muted color."""
        result = get_tier_color("INVALID_TIER")
        assert result == COLORS["text_muted"]

    def test_empty_string_returns_muted(self):
        """Empty string should return muted color."""
        result = get_tier_color("")
        assert result == COLORS["text_muted"]
