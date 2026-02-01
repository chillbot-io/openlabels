"""
OpenLabels Orchestrator - ties adapters, scanner, and scoring together.

This module implements the full pipeline per the architecture specification:

    1. Adapter extracts entities + context from source data
    2. Check scan triggers (should we run the scanner?)
    3. Run scanner if triggered and content is available
    4. Merge adapter + scanner outputs (conservative union)
    5. Score and return result

The Orchestrator is the main entry point for processing files through
the complete OpenLabels pipeline.

Example:
    >>> from openlabels.core.orchestrator import Orchestrator
    >>> from openlabels.adapters import NTFSAdapter
    >>>
    >>> # Create orchestrator with classification enabled
    >>> orchestrator = Orchestrator(enable_classification=True)
    >>>
    >>> # Process a file
    >>> result = orchestrator.process(
    ...     adapter=NTFSAdapter(),
    ...     source_data=acl_data,
    ...     metadata=file_metadata,
    ...     content=file_bytes,
    ... )
    >>> print(f"Score: {result.score}, Tier: {result.tier}")
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .triggers import should_scan, ScanTrigger, calculate_scan_priority
from .constants import CONFIDENCE_WHEN_NO_SPANS
from .merger import merge_inputs_full, MergeResult
from .scorer import score as compute_score, ScoringResult, RiskTier

if TYPE_CHECKING:
    from ..adapters.base import Adapter, NormalizedInput
    from ..context import Context


@dataclass
class ProcessingResult:
    """
    Complete result from processing a file through the pipeline.

    Combines scoring result with additional pipeline metadata.
    """
    # Core scoring
    score: int
    tier: RiskTier
    content_score: float
    exposure_multiplier: float
    co_occurrence_multiplier: float
    co_occurrence_rules: List[str]

    # Pipeline metadata
    scan_triggered: bool
    scan_triggers: List[str]
    scan_priority: int
    sources_used: List[str]

    # Entity details
    entities: Dict[str, int]  # {type: count}
    categories: List[str]
    exposure: str

    # Optional path for reference
    path: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "score": self.score,
            "tier": self.tier.value,
            "content_score": self.content_score,
            "exposure_multiplier": self.exposure_multiplier,
            "co_occurrence_multiplier": self.co_occurrence_multiplier,
            "co_occurrence_rules": self.co_occurrence_rules,
            "scan_triggered": self.scan_triggered,
            "scan_triggers": self.scan_triggers,
            "scan_priority": self.scan_priority,
            "sources_used": self.sources_used,
            "entities": self.entities,
            "categories": self.categories,
            "exposure": self.exposure,
            "path": self.path,
        }


class Orchestrator:
    """
    Orchestrates the full OpenLabels pipeline.

    The orchestrator ties together:
    - Adapters (Macie, DLP, Purview, NTFS, NFS, etc.)
    - Scanner (optional, for content classification)
    - Merger (combines multiple adapter outputs)
    - Scorer (computes risk score)

    Args:
        enable_classification: If True, scanner will run when triggered
        scanner_config: Optional config dict for scanner
        context: Optional Context for resource isolation

    Example:
        >>> # Scenario 1: Metadata only (has vendor labels)
        >>> orchestrator = Orchestrator(enable_classification=False)
        >>> result = orchestrator.process(adapter, source_data, metadata)

        >>> # Scenario 2: Full classification
        >>> orchestrator = Orchestrator(enable_classification=True)
        >>> result = orchestrator.process(adapter, source_data, metadata, content)

        >>> # Scenario 3: With isolated context
        >>> from openlabels import Context
        >>> ctx = Context()
        >>> orchestrator = Orchestrator(enable_classification=True, context=ctx)
    """

    def __init__(
        self,
        enable_classification: bool = False,
        scanner_config: Optional[Dict] = None,
        context: Optional["Context"] = None,
    ):
        """
        Initialize the orchestrator.

        Args:
            enable_classification: Enable scanner for content classification
            scanner_config: Optional scanner configuration overrides
            context: Optional Context for resource isolation.
                    When provided, the scanner uses context resources
                    instead of module-level globals.
        """
        self.enable_classification = enable_classification
        self._scanner = None
        self._scanner_config = scanner_config or {}
        self._context = context

    @property
    def scanner(self):
        """Lazy-load scanner adapter only when needed."""
        if self._scanner is None and self.enable_classification:
            from ..adapters.scanner.scanner_adapter import ScannerAdapter
            self._scanner = ScannerAdapter(context=self._context, **self._scanner_config)
        return self._scanner

    def process(
        self,
        adapter: "Adapter",
        source_data: Any,
        metadata: Dict[str, Any],
        content: Optional[bytes] = None,
    ) -> ProcessingResult:
        """
        Process a file/object through the full pipeline.

        This is the main entry point for the orchestrator. It:
        1. Calls the adapter to get entities + context
        2. Checks scan triggers
        3. Optionally runs the scanner
        4. Merges all inputs
        5. Computes the risk score

        Args:
            adapter: The adapter to use (NTFSAdapter, MacieAdapter, etc.)
            source_data: Adapter-specific source data (ACLs, findings, etc.)
            metadata: File/object metadata
            content: Optional file content for scanning

        Returns:
            ProcessingResult with score, entities, triggers, and metadata

        Example:
            >>> adapter = NTFSAdapter()
            >>> result = orchestrator.process(
            ...     adapter=adapter,
            ...     source_data={"owner": "DOMAIN\\user", "aces": [...]},
            ...     metadata={"path": "\\\\server\\share\\file.docx", "size": 1024},
            ...     content=file_bytes,
            ... )
        """
        from ..adapters.base import NormalizedInput

        # Step 1: Get adapter output
        adapter_input = adapter.extract(source_data, metadata)

        # Step 2: Check if scanning is needed
        should_run, triggers = should_scan(
            adapter_input.entities,
            adapter_input.context,
        )

        # Calculate priority for logging/queueing
        priority = calculate_scan_priority(adapter_input.context, triggers)

        # Step 3: Run scanner if triggered and content available
        inputs: List[NormalizedInput] = [adapter_input]
        scanner_ran = False

        if should_run and self.enable_classification and content is not None:
            scanner_input = self.scanner.extract(content, metadata)
            inputs.append(scanner_input)
            scanner_ran = True

        # Step 4: Merge all inputs
        merge_result = merge_inputs_full(inputs)

        # Step 5: Score
        scoring_result = compute_score(
            entities=merge_result.entity_counts,
            exposure=merge_result.exposure,
            confidence=merge_result.average_confidence,
        )

        # Build final result
        return ProcessingResult(
            score=scoring_result.score,
            tier=scoring_result.tier,
            content_score=scoring_result.content_score,
            exposure_multiplier=scoring_result.exposure_multiplier,
            co_occurrence_multiplier=scoring_result.co_occurrence_multiplier,
            co_occurrence_rules=scoring_result.co_occurrence_rules,
            scan_triggered=scanner_ran,
            scan_triggers=[t.value for t in triggers],
            scan_priority=priority,
            sources_used=list(merge_result.sources),
            entities=merge_result.entity_counts,
            categories=list(scoring_result.categories),
            exposure=merge_result.exposure,
            path=metadata.get("path"),
        )

    def process_content_only(
        self,
        content: bytes,
        metadata: Dict[str, Any],
    ) -> ProcessingResult:
        """
        Process content directly with scanner (no external adapter).

        Use this when you only have raw content and no vendor labels.
        The scanner runs unconditionally since there's no other source.

        Args:
            content: File content as bytes
            metadata: File metadata (name, path, etc.)

        Returns:
            ProcessingResult with score and entities

        Example:
            >>> result = orchestrator.process_content_only(
            ...     content=open("file.pdf", "rb").read(),
            ...     metadata={"name": "file.pdf", "path": "/docs/file.pdf"},
            ... )
        """
        if not self.enable_classification:
            raise ValueError(
                "Scanner not enabled. Set enable_classification=True to use process_content_only()"
            )

        # Run scanner directly
        scanner_input = self.scanner.extract(content, metadata)

        # Score
        from .merger import entities_to_counts

        entity_counts = entities_to_counts(scanner_input.entities)

        # Calculate average confidence
        if scanner_input.entities:
            avg_confidence = sum(e.confidence for e in scanner_input.entities) / len(scanner_input.entities)
        else:
            avg_confidence = CONFIDENCE_WHEN_NO_SPANS

        scoring_result = compute_score(
            entities=entity_counts,
            exposure=scanner_input.context.exposure,
            confidence=avg_confidence,
        )

        return ProcessingResult(
            score=scoring_result.score,
            tier=scoring_result.tier,
            content_score=scoring_result.content_score,
            exposure_multiplier=scoring_result.exposure_multiplier,
            co_occurrence_multiplier=scoring_result.co_occurrence_multiplier,
            co_occurrence_rules=scoring_result.co_occurrence_rules,
            scan_triggered=True,
            scan_triggers=[ScanTrigger.NO_LABELS.value],
            scan_priority=100,  # Maximum priority - no other source
            sources_used=["scanner"],
            entities=entity_counts,
            categories=list(scoring_result.categories),
            exposure=scanner_input.context.exposure,
            path=metadata.get("path"),
        )

    def process_multiple(
        self,
        adapters_data: List[Dict[str, Any]],
        content: Optional[bytes] = None,
    ) -> ProcessingResult:
        """
        Process using multiple adapters (defense in depth).

        Use this when you have data from multiple sources and want to
        merge them together. For example, combining Macie findings with
        scanner results.

        Args:
            adapters_data: List of dicts with keys:
                - adapter: Adapter instance
                - source_data: Adapter-specific source data
                - metadata: File metadata
            content: Optional file content for scanning

        Returns:
            ProcessingResult with merged entities and score

        Example:
            >>> result = orchestrator.process_multiple([
            ...     {"adapter": MacieAdapter(), "source_data": findings, "metadata": s3_meta},
            ...     {"adapter": NTFSAdapter(), "source_data": acl_data, "metadata": file_meta},
            ... ], content=file_bytes)
        """
        from ..adapters.base import NormalizedInput

        if not adapters_data:
            raise ValueError("At least one adapter must be provided")

        inputs: List[NormalizedInput] = []
        all_triggers: List[ScanTrigger] = []
        max_priority = 0

        # Process each adapter
        for item in adapters_data:
            adapter = item["adapter"]
            source_data = item["source_data"]
            metadata = item["metadata"]

            adapter_input = adapter.extract(source_data, metadata)
            inputs.append(adapter_input)

            # Check triggers
            should_run, triggers = should_scan(
                adapter_input.entities,
                adapter_input.context,
            )
            all_triggers.extend(triggers)
            priority = calculate_scan_priority(adapter_input.context, triggers)
            max_priority = max(max_priority, priority)

        # Deduplicate triggers
        unique_triggers = list(set(all_triggers))

        # Run scanner if any adapter triggered it
        scanner_ran = False
        if unique_triggers and self.enable_classification and content is not None:
            # Use metadata from first adapter for scanner
            scanner_metadata = adapters_data[0]["metadata"]
            scanner_input = self.scanner.extract(content, scanner_metadata)
            inputs.append(scanner_input)
            scanner_ran = True

        # Merge all inputs
        merge_result = merge_inputs_full(inputs)

        # Score
        scoring_result = compute_score(
            entities=merge_result.entity_counts,
            exposure=merge_result.exposure,
            confidence=merge_result.average_confidence,
        )

        return ProcessingResult(
            score=scoring_result.score,
            tier=scoring_result.tier,
            content_score=scoring_result.content_score,
            exposure_multiplier=scoring_result.exposure_multiplier,
            co_occurrence_multiplier=scoring_result.co_occurrence_multiplier,
            co_occurrence_rules=scoring_result.co_occurrence_rules,
            scan_triggered=scanner_ran,
            scan_triggers=[t.value for t in unique_triggers],
            scan_priority=max_priority,
            sources_used=list(merge_result.sources),
            entities=merge_result.entity_counts,
            categories=list(scoring_result.categories),
            exposure=merge_result.exposure,
            path=adapters_data[0]["metadata"].get("path"),
        )



# --- Convenience Functions ---


def create_orchestrator(
    enable_classification: bool = False,
    **scanner_config,
) -> Orchestrator:
    """
    Create an Orchestrator with optional configuration.

    Args:
        enable_classification: Enable scanner for content classification
        **scanner_config: Scanner config overrides

    Returns:
        Configured Orchestrator instance
    """
    return Orchestrator(
        enable_classification=enable_classification,
        scanner_config=scanner_config if scanner_config else None,
    )


__all__ = [
    "Orchestrator",
    "ProcessingResult",
    "create_orchestrator",
]
