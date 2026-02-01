"""
Structured Document Extractor

Rule-based PHI extraction for labeled documents (IDs, insurance cards, forms).
Handles 80-90% of structured documents without ML by:
1. Post-processing OCR to fix common issues
2. Detecting field labels (DOB:, NAME:, etc.)
3. Extracting values based on label semantics
4. Pattern-matching unlabeled but structured data

This runs BEFORE ML detection, providing high-confidence extractions
that take precedence in the tier system.
"""

import logging
from dataclasses import dataclass
from typing import List

from ...types import Span
from .ocr_processing import post_process_ocr, map_span_to_original
from .label_detection import detect_labels
from .value_extraction import extract_value, ExtractedField
from .unlabeled_patterns import detect_unlabeled_addresses

logger = logging.getLogger(__name__)


@dataclass
class StructuredExtractionResult:
    """Result of structured document extraction."""
    spans: List[Span]
    processed_text: str  # OCR-corrected text
    labels_found: int
    fields_extracted: int


def extract_structured_phi(text: str) -> StructuredExtractionResult:
    """
    Main entry point for structured document PHI extraction.

    Args:
        text: OCR text from document

    Returns:
        StructuredExtractionResult with detected PHI spans (in original text coordinates)
    """
    # Step 1: Post-process OCR with edit tracking
    processed_text, char_map = post_process_ocr(text)

    # Step 2: Detect labels
    labels = detect_labels(processed_text)

    # Step 3: Extract values for each label
    fields: List[ExtractedField] = []

    for i, label in enumerate(labels):
        next_label = labels[i + 1] if i + 1 < len(labels) else None
        field = extract_value(processed_text, label, next_label)
        if field:
            fields.append(field)

    # Step 4: Convert to spans (still in processed text coordinates)
    processed_spans = []
    for field in fields:
        span = Span(
            start=field.value_start,
            end=field.value_end,
            text=field.value,
            entity_type=field.phi_type,
            confidence=field.confidence,
            detector="structured",
            tier=3,  # STRUCTURED tier - higher than PATTERN
        )
        processed_spans.append(span)

    # Step 5: Detect unlabeled addresses (in processed text)
    address_spans = detect_unlabeled_addresses(processed_text, processed_spans)
    processed_spans.extend(address_spans)

    # Step 6: Map all spans back to original text coordinates
    original_spans = []
    for span in processed_spans:
        orig_start, orig_end = map_span_to_original(
            span.start, span.end, span.text, char_map, text
        )

        # Get the actual text from original at mapped position
        orig_text = text[orig_start:orig_end] if orig_start < len(text) else span.text

        original_spans.append(Span(
            start=orig_start,
            end=orig_end,
            text=orig_text,
            entity_type=span.entity_type,
            confidence=span.confidence,
            detector=span.detector,
            tier=span.tier,
        ))

    logger.debug(
        f"Structured extraction: {len(labels)} labels found, "
        f"{len(fields)} fields extracted, {len(original_spans)} spans"
    )

    return StructuredExtractionResult(
        spans=original_spans,
        processed_text=processed_text,
        labels_found=len(labels),
        fields_extracted=len(fields),
    )
