"""
Tests for output/embed.py backward compatibility module.

Tests that all symbols are properly re-exported from the embed package.
"""

import pytest


class TestEmbedReexports:
    """Tests for re-exported symbols."""

    def test_imports_embedded_label_writer(self):
        """Should re-export EmbeddedLabelWriter."""
        from openlabels.output.embed import EmbeddedLabelWriter
        assert EmbeddedLabelWriter is not None

    def test_imports_xmp_namespace(self):
        """Should re-export OPENLABELS_XMP_NS."""
        from openlabels.output.embed import OPENLABELS_XMP_NS
        assert isinstance(OPENLABELS_XMP_NS, str)
        assert len(OPENLABELS_XMP_NS) > 0

    def test_imports_xmp_prefix(self):
        """Should re-export OPENLABELS_XMP_PREFIX."""
        from openlabels.output.embed import OPENLABELS_XMP_PREFIX
        assert isinstance(OPENLABELS_XMP_PREFIX, str)

    def test_imports_pdf_writer(self):
        """Should re-export PDFLabelWriter."""
        from openlabels.output.embed import PDFLabelWriter
        assert PDFLabelWriter is not None

    def test_imports_office_writer(self):
        """Should re-export OfficeLabelWriter."""
        from openlabels.output.embed import OfficeLabelWriter
        assert OfficeLabelWriter is not None

    def test_imports_image_writer(self):
        """Should re-export ImageLabelWriter."""
        from openlabels.output.embed import ImageLabelWriter
        assert ImageLabelWriter is not None

    def test_imports_get_writer(self):
        """Should re-export get_writer function."""
        from openlabels.output.embed import get_writer
        assert callable(get_writer)

    def test_imports_supports_embedded_labels(self):
        """Should re-export supports_embedded_labels function."""
        from openlabels.output.embed import supports_embedded_labels
        assert callable(supports_embedded_labels)

    def test_imports_write_embedded_label(self):
        """Should re-export write_embedded_label function."""
        from openlabels.output.embed import write_embedded_label
        assert callable(write_embedded_label)

    def test_imports_read_embedded_label(self):
        """Should re-export read_embedded_label function."""
        from openlabels.output.embed import read_embedded_label
        assert callable(read_embedded_label)


class TestAllExports:
    """Tests for __all__ exports."""

    def test_all_is_defined(self):
        """Module should define __all__."""
        import openlabels.output.embed as embed
        assert hasattr(embed, '__all__')
        assert isinstance(embed.__all__, list)

    def test_all_contains_expected_symbols(self):
        """__all__ should contain all expected symbols."""
        from openlabels.output.embed import __all__

        expected = [
            'EmbeddedLabelWriter',
            'OPENLABELS_XMP_NS',
            'OPENLABELS_XMP_PREFIX',
            'PDFLabelWriter',
            'OfficeLabelWriter',
            'ImageLabelWriter',
            'get_writer',
            'supports_embedded_labels',
            'write_embedded_label',
            'read_embedded_label',
        ]

        for symbol in expected:
            assert symbol in __all__, f"{symbol} not in __all__"

    def test_all_symbols_are_importable(self):
        """All symbols in __all__ should be importable."""
        from openlabels.output import embed

        for symbol in embed.__all__:
            assert hasattr(embed, symbol), f"{symbol} not importable"
