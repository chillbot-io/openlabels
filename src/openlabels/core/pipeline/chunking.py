"""
Text chunking for the agent pool pipeline.

Splits large documents into manageable chunks for parallel
NER classification by agent workers.  Each chunk carries
enough overlap to avoid missing entities at boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class TextChunk:
    """A chunk of text extracted from a larger document."""

    text: str
    start: int    # character offset in the original text
    end: int      # character offset end


class TextChunker:
    """Split text into overlapping chunks for NER classification.

    Parameters
    ----------
    max_chunk_size:
        Target characters per chunk.  Defaults to 4 000 which is
        roughly one tokenizer page for most NER models.
    overlap:
        Characters of overlap between consecutive chunks so
        entities straddling a boundary are not missed.
    """

    def __init__(
        self,
        max_chunk_size: int = 4_000,
        overlap: int = 200,
    ) -> None:
        self.max_chunk_size = max_chunk_size
        self.overlap = overlap

    def chunk(self, text: str) -> list[TextChunk]:
        """Split *text* into chunks.

        Short texts (≤ max_chunk_size) are returned as a single chunk.
        """
        if not text:
            return []

        if len(text) <= self.max_chunk_size:
            return [TextChunk(text=text, start=0, end=len(text))]

        chunks: list[TextChunk] = []
        start = 0
        while start < len(text):
            end = min(start + self.max_chunk_size, len(text))

            # Try to break at a whitespace boundary
            if end < len(text):
                break_at = text.rfind(" ", start + self.max_chunk_size // 2, end)
                if break_at != -1:
                    end = break_at + 1  # include the space

            chunks.append(TextChunk(text=text[start:end], start=start, end=end))

            # Advance with overlap
            step = end - start - self.overlap
            if step <= 0:
                step = end - start  # avoid infinite loop on tiny overlap
            start += step

        return chunks
