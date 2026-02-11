"""Tests for text chunking pipeline."""

import pytest

from openlabels.core.pipeline.chunking import TextChunk, TextChunker


class TestTextChunker:
    """Tests for TextChunker.chunk()."""

    def test_empty_text_returns_empty_list(self):
        chunker = TextChunker()
        assert chunker.chunk("") == []

    def test_short_text_returns_single_chunk(self):
        chunker = TextChunker(max_chunk_size=100)
        text = "Hello world"
        chunks = chunker.chunk(text)

        assert len(chunks) == 1
        assert chunks[0].text == text
        assert chunks[0].start == 0
        assert chunks[0].end == len(text)

    def test_text_exactly_at_max_returns_single_chunk(self):
        chunker = TextChunker(max_chunk_size=10)
        text = "0123456789"  # exactly 10 chars
        chunks = chunker.chunk(text)

        assert len(chunks) == 1
        assert chunks[0].text == text

    def test_long_text_splits_into_multiple_chunks(self):
        chunker = TextChunker(max_chunk_size=20, overlap=5)
        text = "word " * 20  # 100 chars
        chunks = chunker.chunk(text)

        assert len(chunks) >= 4, f"100 chars with max_chunk_size=20 should produce at least 4 chunks, got {len(chunks)}"
        # Each chunk has correct offsets and text content
        for chunk in chunks:
            assert chunk.text == text[chunk.start:chunk.end], (
                f"Chunk text does not match offset slice: '{chunk.text}' vs '{text[chunk.start:chunk.end]}'"
            )
            assert len(chunk.text) <= 20, f"Chunk exceeds max_chunk_size: {len(chunk.text)}"
        # First chunk starts at 0, last chunk covers end of text
        assert chunks[0].start == 0
        assert chunks[-1].end == len(text)

    def test_chunks_cover_full_text(self):
        """Every character in the original text appears in at least one chunk."""
        chunker = TextChunker(max_chunk_size=30, overlap=10)
        text = "The quick brown fox jumps over the lazy dog and more text here"
        chunks = chunker.chunk(text)

        covered = set()
        for chunk in chunks:
            for i in range(chunk.start, chunk.end):
                covered.add(i)

        assert covered == set(range(len(text)))

    def test_whitespace_boundary_splitting(self):
        """Chunks should prefer to break at whitespace."""
        chunker = TextChunker(max_chunk_size=15, overlap=3)
        text = "hello world this is a test of chunking"
        chunks = chunker.chunk(text)

        # Chunks should end at or after spaces, not mid-word
        for chunk in chunks[:-1]:  # last chunk can end anywhere
            # The chunk text should end at a word boundary (space or end of text)
            assert chunk.text[-1] == " " or chunk.end == len(text), (
                f"Chunk '{chunk.text}' does not end at whitespace boundary"
            )

    def test_hard_break_when_no_space(self):
        """If there's no space in the search window, chunk at max size."""
        chunker = TextChunker(max_chunk_size=10, overlap=2)
        text = "abcdefghijklmnopqrstuvwxyz"  # no spaces at all
        chunks = chunker.chunk(text)

        assert len(chunks) > 1
        # First chunk should be exactly max_chunk_size
        assert len(chunks[0].text) == 10

    def test_offset_accuracy(self):
        """chunk.start/end should index correctly into original text."""
        chunker = TextChunker(max_chunk_size=20, overlap=5)
        text = "alpha bravo charlie delta echo foxtrot golf hotel india"
        chunks = chunker.chunk(text)

        for chunk in chunks:
            assert text[chunk.start:chunk.end] == chunk.text

    def test_overlap_preserved(self):
        """Adjacent chunks should share overlap characters."""
        chunker = TextChunker(max_chunk_size=30, overlap=10)
        text = "a " * 50  # 100 chars
        chunks = chunker.chunk(text)

        assert len(chunks) >= 2
        for i in range(len(chunks) - 1):
            current = chunks[i]
            nxt = chunks[i + 1]
            # The next chunk should start before the current one ends
            assert nxt.start < current.end, (
                f"No overlap between chunk {i} (end={current.end}) "
                f"and chunk {i+1} (start={nxt.start})"
            )

    def test_step_size_guard_prevents_infinite_loop(self):
        """When overlap >= chunk size, step should still be positive."""
        # overlap larger than effective chunk size
        chunker = TextChunker(max_chunk_size=5, overlap=10)
        text = "hello world testing"
        # Should complete without hanging
        chunks = chunker.chunk(text)
        assert len(chunks) >= 1
        # All text covered
        assert chunks[-1].end == len(text)

    @pytest.mark.parametrize("size", [1, 5, 50, 500, 5000])
    def test_various_chunk_sizes(self, size):
        """Chunking should work with various max_chunk_size values."""
        chunker = TextChunker(max_chunk_size=size, overlap=min(size // 4, 50))
        text = "word " * 200
        chunks = chunker.chunk(text)

        assert len(chunks) >= 1
        # First chunk starts at 0
        assert chunks[0].start == 0
        # Last chunk ends at text length
        assert chunks[-1].end == len(text)

    def test_default_parameters(self):
        """Default chunker uses 4000 chars / 200 overlap."""
        chunker = TextChunker()
        assert chunker.max_chunk_size == 4000
        assert chunker.overlap == 200
