"""Shared test fixtures for ScrubIQ tests.

This module provides factory functions and fixtures for creating test spans
and other test data. All fixtures create valid objects that pass validation.
"""

import pytest
from scrubiq.types import Span, Tier


def make_span(
    text: str,
    start: int = 0,
    entity_type: str = "NAME",
    confidence: float = 0.9,
    detector: str = "test",
    tier: int = 2,
    **kwargs
) -> Span:
    """Factory function to create a valid Span for testing.

    Automatically calculates end position from start + len(text).
    This ensures span text length always matches span boundaries.

    Args:
        text: The span text content
        start: Start position in document (default 0)
        entity_type: Entity type (default NAME)
        confidence: Confidence score 0.0-1.0 (default 0.9)
        detector: Detector name (default "test")
        tier: Authority tier 1-4 (default 2 = PATTERN)
        **kwargs: Additional Span fields (safe_harbor_value, needs_review, etc.)

    Returns:
        A valid Span object
    """
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
        **kwargs
    )


def make_spans_from_text(text: str, annotations: list) -> list:
    """Create spans from a text string and list of annotations.

    Args:
        text: The source text
        annotations: List of (start, end, entity_type, confidence, detector, tier) tuples
            or dicts with those keys

    Returns:
        List of Span objects

    Example:
        text = "John Smith lives in NYC"
        spans = make_spans_from_text(text, [
            (0, 10, "NAME", 0.9, "ml", 1),
            (20, 23, "ADDRESS", 0.8, "pattern", 2),
        ])
    """
    spans = []
    for ann in annotations:
        if isinstance(ann, dict):
            start = ann["start"]
            end = ann["end"]
            entity_type = ann.get("entity_type", "NAME")
            confidence = ann.get("confidence", 0.9)
            detector = ann.get("detector", "test")
            tier = ann.get("tier", 2)
        else:
            start, end, entity_type, confidence, detector, tier = ann

        spans.append(Span(
            start=start,
            end=end,
            text=text[start:end],
            entity_type=entity_type,
            confidence=confidence,
            detector=detector,
            tier=Tier.from_value(tier),
        ))
    return spans


@pytest.fixture
def span_factory():
    """Fixture providing the make_span factory function."""
    return make_span


@pytest.fixture
def spans_from_text():
    """Fixture providing the make_spans_from_text factory function."""
    return make_spans_from_text


# Common test texts
CLINICAL_NOTE = """
Patient: John Smith
DOB: 01/15/1980
MRN: 123456789

Dr. Sarah Johnson, MD reviewed the patient's case.
The patient presents with chest pain. Contact: 555-123-4567.
Email: john.smith@email.com

Address: 123 Main Street, Springfield, IL 62701
"""

ID_CARD_TEXT = """
DRIVER'S LICENSE
DLN: D123-4567-8901
CLASS: C
NAME: JOHN SMITH
DOB: 01/15/1980
DUPS: 000
4bEXP: 01/15/2028
RESTR: NONE
"""

SHIPPING_CONTEXT = """
Your package has been shipped!
USPS Tracking: 9400111899223456789012
FedEx: 123456789012
Estimated delivery: January 25, 2026
"""


@pytest.fixture
def clinical_note():
    """Sample clinical note text for testing."""
    return CLINICAL_NOTE


@pytest.fixture
def id_card_text():
    """Sample ID card text for testing."""
    return ID_CARD_TEXT


@pytest.fixture
def shipping_context():
    """Sample shipping/tracking context for testing."""
    return SHIPPING_CONTEXT
