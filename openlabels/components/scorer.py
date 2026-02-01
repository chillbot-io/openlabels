"""
OpenLabels Scorer Component.

Handles all risk scoring operations.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union, TYPE_CHECKING

from ..adapters.base import Adapter, NormalizedInput
from ..core.scorer import ScoringResult, score as score_entities
from ..core.entity_types import normalize_entity_type
from ..core.constants import CONFIDENCE_WHEN_NO_SPANS

if TYPE_CHECKING:
    from ..context import Context


class Scorer:
    """
    Risk scoring component.

    Handles:
    - score_file(): Score a local file
    - score_text(): Score text content
    - score_from_adapters(): Score from pre-extracted adapter outputs

    Example:
        >>> from openlabels import Context
        >>> from openlabels.components import Scorer
        >>>
        >>> ctx = Context()
        >>> scorer = Scorer(ctx)
        >>> result = scorer.score_file("data.csv")
        >>> print(f"Risk: {result.score}")
    """

    def __init__(self, context: "Context"):
        self._ctx = context

    @property
    def default_exposure(self) -> str:
        return self._ctx.default_exposure

    def score_file(
        self,
        path: Union[str, Path],
        adapters: Optional[List[Adapter]] = None,
        exposure: Optional[str] = None,
    ) -> ScoringResult:
        """
        Score a local file for data risk.

        Args:
            path: Path to file to scan
            adapters: Optional list of adapters. If None, uses built-in scanner.
            exposure: Exposure level override (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC).

        Returns:
            ScoringResult with score, tier, and breakdown
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        exposure = (exposure or self.default_exposure).upper()

        if adapters:
            inputs = []
            for adapter in adapters:
                normalized = adapter.extract(path, {"path": str(path)})
                inputs.append(normalized)
            return self.score_from_adapters(inputs, exposure=exposure)

        # Default: use built-in scanner with context for isolation
        from ..adapters.scanner import detect_file

        detection_result = detect_file(path, context=self._ctx)
        entities = self._normalize_entity_counts(detection_result.entity_counts)
        confidence = self._calculate_average_confidence(detection_result.spans)

        return score_entities(entities, exposure=exposure, confidence=confidence)

    def score_text(
        self,
        text: str,
        exposure: Optional[str] = None,
    ) -> ScoringResult:
        """
        Score text content for data risk.

        Args:
            text: Text to scan for sensitive data
            exposure: Exposure level (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC)

        Returns:
            ScoringResult with score, tier, and breakdown
        """
        from ..adapters.scanner import detect

        exposure = (exposure or self.default_exposure).upper()

        # Pass context for resource isolation
        detection_result = detect(text, context=self._ctx)
        entities = self._normalize_entity_counts(detection_result.entity_counts)
        confidence = self._calculate_average_confidence(detection_result.spans)

        return score_entities(entities, exposure=exposure, confidence=confidence)

    def score_from_adapters(
        self,
        inputs: List[NormalizedInput],
        exposure: Optional[str] = None,
    ) -> ScoringResult:
        """
        Score from pre-extracted adapter outputs.

        Args:
            inputs: List of NormalizedInput from adapters
            exposure: Exposure level override.

        Returns:
            ScoringResult with score, tier, and breakdown
        """
        if not inputs:
            return score_entities({}, exposure=self.default_exposure)

        merged_entities, avg_confidence = self._merge_inputs(inputs)

        if exposure:
            final_exposure = exposure.upper()
        else:
            final_exposure = self._get_highest_exposure(inputs)

        return score_entities(
            merged_entities,
            exposure=final_exposure,
            confidence=avg_confidence,
        )

    def _normalize_entity_counts(
        self,
        entity_counts: Dict[str, int],
    ) -> Dict[str, int]:
        """Normalize entity type names to UPPERCASE."""
        return {
            normalize_entity_type(entity_type): count
            for entity_type, count in entity_counts.items()
        }

    def _calculate_average_confidence(self, spans) -> float:
        """Calculate average confidence from detection spans."""
        if not spans:
            return CONFIDENCE_WHEN_NO_SPANS

        total_confidence = sum(span.confidence for span in spans)
        return total_confidence / len(spans)

    def _merge_inputs(
        self,
        inputs: List[NormalizedInput],
    ) -> tuple:
        """
        Merge entities from multiple adapter inputs.

        Returns:
            Tuple of (merged_entities dict, average_confidence)
        """
        merged: Dict[str, Dict] = {}

        for inp in inputs:
            for entity in inp.entities:
                entity_type = normalize_entity_type(entity.type)

                if entity_type not in merged:
                    merged[entity_type] = {
                        "count": entity.count,
                        "confidence": entity.confidence,
                    }
                else:
                    merged[entity_type]["count"] = max(
                        merged[entity_type]["count"],
                        entity.count,
                    )
                    merged[entity_type]["confidence"] = max(
                        merged[entity_type]["confidence"],
                        entity.confidence,
                    )

        entities = {etype: data["count"] for etype, data in merged.items()}

        if merged:
            avg_confidence = sum(
                data["confidence"] for data in merged.values()
            ) / len(merged)
        else:
            avg_confidence = CONFIDENCE_WHEN_NO_SPANS

        return entities, avg_confidence

    def _get_highest_exposure(self, inputs: List[NormalizedInput]) -> str:
        """Get the highest exposure level from inputs."""
        exposure_order = ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]

        highest_idx = 0
        for inp in inputs:
            exposure = inp.context.exposure.upper()
            if exposure in exposure_order:
                idx = exposure_order.index(exposure)
                highest_idx = max(highest_idx, idx)

        return exposure_order[highest_idx]
