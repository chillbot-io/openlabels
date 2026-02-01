"""
Scanner as an Adapter - wraps Detector with standard adapter interface.

This module provides the ScannerAdapter class that implements the standard
Adapter interface, allowing the scanner to be used alongside other adapters
(Macie, DLP, Purview, etc.) in the orchestration pipeline.

Per the architecture:
    "The scanner is an adapter like any other. It produces the same normalized output."

Example:
    >>> from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
    >>> adapter = ScannerAdapter()
    >>> result = adapter.extract(content=file_bytes, metadata={"name": "file.pdf"})
    >>> # Returns NormalizedInput with entities and context
"""

import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..base import (
    Entity,
    NormalizedContext,
    NormalizedInput,
    EntityAggregator,
    calculate_staleness_days,
    is_archive,
)
from ...core.registry import normalize_type
from .adapter import Detector
from .config import Config
from .types import Span

if TYPE_CHECKING:
    from ...context import Context


class ScannerAdapter:
    """
    Scanner adapter - detects entities in content.

    Implements the same interface as other adapters:
        extract(source_data, metadata) -> NormalizedInput

    This wraps the existing Detector class to provide a standard adapter
    interface for use in the orchestration pipeline.

    Args:
        config: Optional scanner configuration
        context: Optional Context for resource isolation
        **config_kwargs: Additional config overrides (min_confidence, etc.)

    Example:
        >>> adapter = ScannerAdapter(min_confidence=0.7)
        >>> with open("document.pdf", "rb") as f:
        ...     content = f.read()
        >>> result = adapter.extract(content, {"name": "document.pdf", "path": "/docs/document.pdf"})
        >>> print(result.entities)  # List of Entity objects

        >>> # With context for isolation:
        >>> from openlabels import Context
        >>> ctx = Context()
        >>> adapter = ScannerAdapter(context=ctx)
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        context: Optional["Context"] = None,
        **config_kwargs,
    ):
        """
        Initialize the scanner adapter.

        Args:
            config: Optional Config object. If not provided, uses defaults.
            context: Optional Context for resource isolation.
                    When provided, the underlying detector uses context
                    resources instead of module-level globals.
            **config_kwargs: Config overrides (min_confidence, enable_ml, etc.)
        """
        if config is None:
            config = Config.from_env()
            for key, value in config_kwargs.items():
                if hasattr(config, key):
                    setattr(config, key, value)

            config.__post_init__()  # HIGH-006: re-validate after setattr

        self._detector = Detector(config=config, context=context)
        self._config = config
        self._context = context

    @property
    def detector(self) -> Detector:
        """Access the underlying Detector instance."""
        return self._detector

    def extract(
        self,
        content: bytes,
        metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Extract entities from content and normalize context.

        This is the standard adapter interface method. It takes raw content
        bytes and file metadata, extracts text, runs detection, and returns
        normalized entities and context.

        Args:
            content: File content as bytes
            metadata: File metadata dict with keys like:
                - name: Filename (required for format detection)
                - path: Full file path
                - size: File size in bytes
                - last_modified: ISO timestamp
                - last_accessed: ISO timestamp
                - exposure: Exposure level (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC)
                - encryption: Encryption status (none, platform, customer_managed)
                - owner: File owner

        Returns:
            NormalizedInput with entities list and context
        """
        start_time = time.perf_counter()

        # Extract text from content
        text = self._extract_text(content, metadata.get("name", "unknown"))

        # Run detection
        detection_result = self._detector.detect(text)

        # Convert spans to entities
        entities = self._spans_to_entities(detection_result.spans)

        # Build context from metadata
        context = self._build_context(
            metadata,
            processing_time_ms=(time.perf_counter() - start_time) * 1000,
        )

        return NormalizedInput(entities=entities, context=context)

    def extract_from_text(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedInput:
        """
        Extract entities from pre-extracted text.

        Use this when you already have text extracted and don't need
        the adapter to handle file format detection.

        Args:
            text: Text content to scan
            metadata: Optional metadata dict

        Returns:
            NormalizedInput with entities and context
        """
        metadata = metadata or {}

        # Run detection directly
        detection_result = self._detector.detect(text)

        # Convert spans to entities
        entities = self._spans_to_entities(detection_result.spans)

        # Build context
        context = self._build_context(metadata)

        return NormalizedInput(entities=entities, context=context)

    def _extract_text(self, content: bytes, filename: str) -> str:
        """Extract text from content bytes using the scanner's extractors."""
        from .extractors import extract_text

        result = extract_text(content, filename)
        return result.text

    def _spans_to_entities(self, spans: List[Span]) -> List[Entity]:
        """
        Convert detector spans to normalized Entity objects.

        Aggregates multiple spans of the same type into a single Entity
        with the total count and maximum confidence.

        Args:
            spans: List of Span objects from detector

        Returns:
            List of Entity objects
        """
        agg = EntityAggregator(source="scanner")

        for span in spans:
            # Normalize entity type to canonical form
            entity_type = normalize_type(span.entity_type, "scanner")
            agg.add(
                entity_type,
                count=1,
                confidence=span.confidence,
                positions=[(span.start, span.end)],
            )

        return agg.to_entities()

    def _build_context(
        self,
        metadata: Dict[str, Any],
        processing_time_ms: float = 0.0,
    ) -> NormalizedContext:
        """
        Build NormalizedContext from file metadata.

        Args:
            metadata: File metadata dict
            processing_time_ms: Time spent processing (for logging)

        Returns:
            NormalizedContext object
        """
        path = metadata.get("path", "")

        return NormalizedContext(
            # Exposure - default to PRIVATE if not specified
            exposure=metadata.get("exposure", "PRIVATE"),
            cross_account_access=metadata.get("cross_account_access", False),
            anonymous_access=metadata.get("anonymous_access", False),

            # Protection
            encryption=metadata.get("encryption", "none"),
            versioning=metadata.get("versioning", False),
            access_logging=metadata.get("access_logging", False),
            retention_policy=metadata.get("retention_policy", False),

            # Timestamps
            last_modified=metadata.get("last_modified"),
            last_accessed=metadata.get("last_accessed"),
            staleness_days=calculate_staleness_days(metadata.get("last_modified")),

            # Classification - scanner provides it
            has_classification=True,
            classification_source="scanner",

            # File info
            path=path,
            owner=metadata.get("owner"),
            size_bytes=metadata.get("size", len(metadata.get("content", b""))),
            file_type=metadata.get("content_type", metadata.get("file_type", "")),
            is_archive=is_archive(path),
        )



# --- Convenience Functions ---


def create_scanner_adapter(
    context: Optional["Context"] = None,
    **kwargs,
) -> ScannerAdapter:
    """
    Create a ScannerAdapter with optional configuration.

    Args:
        context: Optional Context for resource isolation.
        **kwargs: Config overrides (min_confidence, enable_ml, etc.)

    Returns:
        Configured ScannerAdapter instance
    """
    return ScannerAdapter(context=context, **kwargs)


__all__ = [
    "ScannerAdapter",
    "create_scanner_adapter",
]
