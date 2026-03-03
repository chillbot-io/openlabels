"""Coordinates parallel detectors with deduplication and post-processing."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from openlabels.core.constants import DETECTOR_TIMEOUT
from openlabels.exceptions import DetectionError

from ..pipeline.confidence import calibrate_spans
from ..pipeline.span_resolver import resolve_spans
from ..policies.engine import get_policy_engine
from ..policies.schema import EntityMatch
from ..types import DetectionResult, Span, Tier, normalize_entity_type
from .base import BaseDetector
from .config import DetectionConfig
from .language import LanguageResult, detect_language, should_run_detector
from .post_processing import (
    _calibrated_threshold,
    _corroboration_group,
    _ranges_overlap,
    _split_name_spans,
    _suppress_uncorroborated_ml,
)
from .registry import create_detector
from .suppressors import (
    _correct_type_confusions,
    _suppress_ml_location_false_positives,
    _suppress_ml_name_collisions,
    _suppress_ml_name_false_positives,
    _suppress_ml_username_false_positives,
    _suppress_name_location_collisions,
    _suppress_pronoun_names,
)

logger = logging.getLogger(__name__)

# Default confidence threshold for filtering
DEFAULT_CONFIDENCE_THRESHOLD = 0.70


class DetectorOrchestrator:
    """Runs detectors in parallel, deduplicates results, and applies post-processing."""

    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()
        self.confidence_threshold = self.config.confidence_threshold
        self.max_workers = self.config.max_workers
        self.detectors: list[BaseDetector] = []
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self._using_hyperscan = False
        self._entity_threshold_map: dict[str, float] = dict(
            self.config.entity_thresholds
        )

        if self.config.enable_hyperscan:
            self._init_hyperscan_detector()

        _CONFIG_TO_DETECTORS: list[tuple[str, list[str]]] = [
            ("enable_checksum", ["checksum"]),
            ("enable_secrets", ["secrets"]),
            ("enable_financial", ["financial"]),
            ("enable_government", ["government"]),
            ("enable_patterns", ["pattern", "additional_patterns"]),
            ("enable_dictionary_names", ["dictionary_names"]),
        ]

        for flag, names in _CONFIG_TO_DETECTORS:
            if getattr(self.config, flag):
                for name in names:
                    try:
                        self.detectors.append(create_detector(name))
                    except KeyError:
                        logger.warning("Detector %r not registered — skipping", name)

        if self.config.enable_ml:
            self._init_ml_detectors(self.config.ml_model_dir, self.config.use_onnx)

        if self.config.enable_phi:
            self._init_phi_detector()

        # Load multilingual GLiNER if explicitly enabled, or if ML + language
        # detection are both on (so the gating logic can route non-English text
        # to the multilingual model).
        if self.config.enable_multilingual or (
            self.config.enable_ml and self.config.enable_language_detection
        ):
            self._init_multilingual_gliner()

        self._coref_resolver: Callable[..., list[Span]] | None = None
        self._context_enhancer: Any = None
        if self.config.enable_coref or self.config.enable_context_enhancement:
            self._init_pipeline(
                self.config.enable_coref,
                self.config.enable_context_enhancement,
            )

        self._ml_loaded = any(
            d.name in ("gliner", "multilingual_gliner") for d in self.detectors
        )
        self._phi_loaded = any(d.name == "stanford_phi" for d in self.detectors)

        logger.info(
            f"DetectorOrchestrator initialized with {len(self.detectors)} detectors: "
            f"{[d.name for d in self.detectors]}"
            f"{' (Hyperscan accelerated)' if self._using_hyperscan else ''}"
        )

        # Loud warnings when requested detectors failed to load
        if self.config.enable_ml and not self._ml_loaded:
            logger.warning(
                "ML was requested but NO ML detectors loaded! "
                "Results will use pattern-only detection."
            )
        if self.config.enable_phi and not self._phi_loaded:
            logger.warning(
                "PHI was requested but PHI detector failed to load!"
            )

    @property
    def ml_loaded(self) -> bool:
        """True if at least one ML detector is active."""
        return self._ml_loaded

    @property
    def phi_loaded(self) -> bool:
        """True if the PHI detector is active."""
        return self._phi_loaded

    @property
    def detector_names(self) -> list[str]:
        """Names of all active detectors."""
        return [d.name for d in self.detectors]

    def _init_hyperscan_detector(self) -> None:
        """Initialize Hyperscan-accelerated detector."""
        try:
            from .hyperscan import SUPPLEMENTAL_PATTERNS, HyperscanDetector

            hyperscan_detector = HyperscanDetector(
                additional_patterns=SUPPLEMENTAL_PATTERNS
            )
            self.detectors.append(hyperscan_detector)
            self._using_hyperscan = hyperscan_detector.using_hyperscan
            logger.info(
                f"Hyperscan detector initialized with {hyperscan_detector.pattern_count} patterns"
                f" ({'SIMD-accelerated' if self._using_hyperscan else 'Python fallback'})"
            )
        except (ImportError, RuntimeError, OSError, ValueError) as e:
            logger.warning(f"Failed to initialize Hyperscan detector: {e}")

    def _init_ml_detectors(
        self,
        model_dir: Path | None,
        use_onnx: bool = True
    ) -> None:
        """Initialize ML-based detectors (GLiNER)."""
        try:
            from .gliner import GLiNERDetector

            gliner = GLiNERDetector(
                model_name=self.config.gliner_model,
                threshold=self.config.gliner_threshold,
                use_onnx=use_onnx,
                enable_label_selection=self.config.enable_label_selection,
            )
            if gliner.load():
                self.detectors.append(gliner)
                logger.info("GLiNER detector loaded: %s", self.config.gliner_model)
            else:
                logger.warning("GLiNER detector failed to load")

        except ImportError as e:
            logger.warning("GLiNER detector not available: %s", e)

    def _init_phi_detector(self) -> None:
        """Initialize Stanford PHI de-identification detector."""
        try:
            from .phi_detector import StanfordPHIDetector

            phi = StanfordPHIDetector(
                threshold=self.config.phi_threshold,
            )
            if phi.load():
                self.detectors.append(phi)
                logger.info("Stanford PHI detector loaded: %s", self.config.phi_model)
            else:
                logger.warning("Stanford PHI detector failed to load")

        except ImportError as e:
            logger.warning("Stanford PHI detector not available: %s", e)

    def _init_multilingual_gliner(self) -> None:
        """Initialize multilingual GLiNER detector (9 EU languages)."""
        try:
            from .multilingual_gliner import MultilingualGLiNERDetector

            ml_gliner = MultilingualGLiNERDetector(
                model_name=self.config.multilingual_gliner_model,
                threshold=self.config.multilingual_gliner_threshold,
                use_onnx=self.config.use_onnx,
                enable_label_selection=self.config.enable_label_selection,
            )
            if ml_gliner.load():
                self.detectors.append(ml_gliner)
                logger.info(
                    "Multilingual GLiNER detector loaded: %s",
                    self.config.multilingual_gliner_model,
                )
            else:
                logger.warning("Multilingual GLiNER detector failed to load")

        except ImportError as e:
            logger.warning("Multilingual GLiNER detector not available: %s", e)

    def _init_pipeline(
        self,
        enable_coref: bool,
        enable_context_enhancement: bool
    ) -> None:
        """Initialize post-processing pipeline components."""
        if enable_coref:
            try:
                from ..pipeline import resolve_coreferences
                self._coref_resolver = resolve_coreferences
                logger.info("Coreference resolution enabled")
            except ImportError as e:
                logger.warning(f"Coreference resolution not available: {e}")

        if enable_context_enhancement:
            try:
                from ..pipeline import create_enhancer
                self._context_enhancer = create_enhancer()
                logger.info("Context enhancement enabled")
            except ImportError as e:
                logger.warning(f"Context enhancement not available: {e}")

    async def detect(self, text: str) -> DetectionResult:
        """Async wrapper around detect_sync via run_in_executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.detect_sync, text)

    def detect_sync(self, text: str) -> DetectionResult:
        """Run all detectors on the input text (synchronous entry point)."""
        start_time = time.time()

        if not text or not text.strip():
            return DetectionResult(
                spans=[],
                entity_counts={},
                processing_time_ms=0.0,
                detectors_used=[],
                text_length=0,
            )

        # Language-gated detection: determine which detectors to run.
        lang_result: LanguageResult | None = None
        if self.config.enable_language_detection:
            lang_result = detect_language(text)
            logger.debug(
                "Language detection: %s (%.2f, %s)",
                lang_result.language_code,
                lang_result.confidence,
                lang_result.tier.value,
            )

        # Select detectors based on detected language.
        if lang_result is not None:
            active_detectors = [
                d for d in self.detectors
                if should_run_detector(d.name, lang_result)
            ]
            skipped = set(d.name for d in self.detectors) - set(d.name for d in active_detectors)
            if skipped:
                logger.info(
                    "Language gating (%s): skipped detectors %s",
                    lang_result.language_code,
                    sorted(skipped),
                )
        else:
            active_detectors = self.detectors

        all_spans: list[Span] = []
        detectors_used: list[str] = []

        future_to_detector = {
            self._executor.submit(self._run_detector, detector, text): detector
            for detector in active_detectors
        }

        try:
            for future in as_completed(future_to_detector, timeout=DETECTOR_TIMEOUT):
                detector = future_to_detector[future]
                try:
                    spans = future.result()
                    all_spans.extend(spans)
                    if spans:
                        detectors_used.append(detector.name)
                except (DetectionError, RuntimeError, ValueError, OSError) as e:
                    logger.error(f"Detector {detector.name} failed: {e}")
        except TimeoutError:
            timed_out = [
                future_to_detector[f].name
                for f in future_to_detector
                if not f.done()
            ]
            logger.error(f"Detector timeout ({DETECTOR_TIMEOUT}s): {timed_out}")

        # Gate multilingual GLiNER from ensemble voting on English text.
        # On English, the multilingual model is a noisier duplicate of the
        # primary GLiNER — two GLiNERs agreeing on a FP inflates the
        # ensemble boost.  However, for name-family and location-family
        # types, the multilingual model adds value (non-Western names,
        # international locations) so we allow partial voting (0.5x
        # weight) for those categories instead of full exclusion.
        ensemble_excluded: frozenset[str] = frozenset()
        ensemble_partial: frozenset[str] = frozenset()
        if lang_result is not None and lang_result.is_english:
            ensemble_excluded = frozenset({"gliner_multilingual"})
            ensemble_partial = frozenset({"gliner_multilingual"})

        processed_spans = self._post_process(
            all_spans, text=text,
            ensemble_excluded=ensemble_excluded,
            ensemble_partial=ensemble_partial,
        )

        if self.config.enable_allowlist and processed_spans:
            from .allowlist import get_allowlist
            processed_spans = get_allowlist().filter_spans(processed_spans)

        if self._coref_resolver and processed_spans:
            try:
                processed_spans = self._coref_resolver(text, processed_spans)
            except (RuntimeError, ValueError, IndexError) as e:
                logger.error(f"Coreference resolution failed: {e}")

        # Suppress pronouns detected as NAME-family entities.  The PHI model
        # (trained for Safe Harbor de-identification) and the coref resolver
        # both produce pronoun spans — but bare pronouns are not PII.
        if processed_spans:
            processed_spans = _suppress_pronoun_names(processed_spans)

        if self._context_enhancer and processed_spans:
            try:
                processed_spans = self._context_enhancer.enhance(text, processed_spans)
            except (RuntimeError, ValueError, IndexError) as e:
                logger.error(f"Context enhancement failed: {e}")

        policy_result = None
        if self.config.enable_policy and processed_spans:
            try:
                entity_matches = [
                    EntityMatch(
                        entity_type=span.entity_type,
                        value=span.text,
                        confidence=span.confidence,
                        start=span.start,
                        end=span.end,
                        source=span.detector,
                    )
                    for span in processed_spans
                ]
                policy_result = get_policy_engine().evaluate(entity_matches)
            except (ValueError, KeyError, RuntimeError) as e:
                logger.error(f"Policy evaluation failed: {e}")

        entity_counts: dict[str, int] = {}
        for span in processed_spans:
            normalized = normalize_entity_type(span.entity_type)
            entity_counts[normalized] = entity_counts.get(normalized, 0) + 1

        processing_time_ms = (time.time() - start_time) * 1000

        return DetectionResult(
            spans=processed_spans,
            entity_counts=entity_counts,
            processing_time_ms=processing_time_ms,
            detectors_used=detectors_used,
            text_length=len(text),
            policy_result=policy_result,
        )

    def _run_detector(self, detector: BaseDetector, text: str) -> list[Span]:
        """Run a single detector with error handling."""
        try:
            if not detector.is_available():
                logger.warning(f"Detector {detector.name} not available")
                return []
            return detector.detect(text)
        except (DetectionError, RuntimeError, ValueError, OSError) as e:
            logger.error(f"Error in detector {detector.name}: {e}")
            return []

    def shutdown(self) -> None:
        """Shut down the persistent thread pool."""
        self._executor.shutdown(wait=False)

    def _passes_threshold(self, span: Span) -> bool:
        """Check if a span meets its confidence threshold.

        Per-entity thresholds take priority, then ML vs global threshold.
        """
        entity_thresh = self._entity_threshold_map.get(span.entity_type)
        if entity_thresh is not None:
            return span.confidence >= entity_thresh
        if span.tier == Tier.ML:
            return span.confidence >= self.config.ml_confidence_threshold
        return span.confidence >= self.confidence_threshold

    # Ensemble boost range when 2+ detectors agree on the same span.
    # Actual boost is scaled by the minimum raw confidence of the
    # agreeing detectors — well-calibrated agreement gets a larger boost.
    _ENSEMBLE_BOOST_MIN = 0.10
    _ENSEMBLE_BOOST_MAX = 0.20

    def _post_process(
        self,
        spans: list[Span],
        text: str | None = None,
        ensemble_excluded: frozenset[str] = frozenset(),
        ensemble_partial: frozenset[str] = frozenset(),
    ) -> list[Span]:
        """Post-process: filter, context-adjust, calibrate, ensemble, deduplicate.

        Pipeline order:
        1. Filter by per-entity / per-tier raw confidence threshold
        2. Apply context keyword boost/demote (on raw confidence)
        3. Calibrate into unified tier bands
        4. Ensemble boost (when 2+ detectors agree)
        5. Suppress ML name fragments that collide with pattern detections
        6. Resolve overlapping spans
        7. Suppress uncorroborated ML detections for pattern-covered types
        8. Proximity boost (optional)

        Args:
            ensemble_excluded: Detector names excluded from ensemble voting
                (e.g. ``{"gliner_multilingual"}`` on English text).
            ensemble_partial: Detector names that get partial voting weight
                (0.5x) for name/location categories on English text.
        """
        filtered = [s for s in spans if self._passes_threshold(s)]

        # Context keyword adjustment (before calibration)
        if self.config.enable_context_keywords and text and filtered:
            from ..pipeline.context_keywords import apply_context_keywords
            filtered = apply_context_keywords(filtered, text)

        calibrated = calibrate_spans(filtered)

        # Ensemble boost: when multiple detectors agree on overlapping
        # spans with the same entity type, boost the best span's confidence.
        calibrated = self._apply_ensemble_boost(
            calibrated, ensemble_excluded, ensemble_partial,
        )

        # Pre-dedup: suppress ML FIRSTNAME/LASTNAME fragments that overlap
        # with pattern detections of more specific types (USERNAME, CITY,
        # STATE, etc.).  Without this, ML names absorb pattern detections
        # in HIGHER_TIER dedup, causing USERNAME and location misses.
        calibrated = _suppress_ml_name_collisions(calibrated)

        from ..pipeline.span_resolver import OverlapStrategy

        resolved = resolve_spans(
            calibrated,
            confidence_threshold=0.0,
            strategy=OverlapStrategy.HIGHER_TIER,
            source_text=text,
        )

        # Split multi-word NAME / NAME_PATIENT spans into FIRSTNAME + LASTNAME
        # so they align with benchmark gold annotations that label each name
        # part separately.
        resolved = _split_name_spans(resolved)

        # Suppress uncorroborated ML detections: ML spans for entity types
        # that patterns handle well (dates, addresses, financial, etc.) are
        # suppressed unless they were ensemble-boosted or have high confidence.
        # ML should primarily contribute names and rare professional
        # entities — things patterns cannot detect.
        resolved = _suppress_uncorroborated_ml(resolved, calibrated)

        # Suppress FIRSTNAME/LASTNAME that collide with priority types
        # (locations, COMPANY, USERNAME, JOB_TITLE).  Uses the pre-dedup
        # calibrated list so we see GLiNER detections that lost to
        # FIRSTNAME in dedup (e.g. "Florence" detected as both CITY
        # and FIRSTNAME by GLiNER).
        resolved = _suppress_name_location_collisions(
            resolved, all_candidates=calibrated,
        )

        # Correct type confusions: reclassify ML spans that match a more
        # specific type's format (USERNAME→FIRSTNAME, PHONE→SSN, etc.)
        resolved = _correct_type_confusions(resolved, source_text=text)

        # Suppress ML name spans whose text is a common English word
        # that GLiNER falsely labels as FIRSTNAME/LASTNAME.
        resolved = _suppress_ml_name_false_positives(resolved)

        # Suppress ML USERNAME spans that are common English words
        resolved = _suppress_ml_username_false_positives(resolved)

        # Suppress ML CITY/location spans that are common English words
        resolved = _suppress_ml_location_false_positives(resolved)

        if self.config.enable_proximity_boost and resolved:
            from ..pipeline.entity_proximity import analyze_proximity
            proximity = analyze_proximity(
                resolved,
                proximity_chars=self.config.proximity_window_chars,
            )
            if proximity.boost_count:
                logger.debug(
                    "Proximity boosting: %d/%d spans boosted across %d clusters",
                    proximity.boost_count,
                    proximity.original_span_count,
                    len(proximity.clusters),
                )
            resolved = proximity.boosted_spans

        return resolved

    # Extra boost when 3+ detectors agree (stacks with base boost).
    # Raised from 0.08 to 0.12: with 3 ML models, triple agreement is
    # a very strong signal — reward it more to recover TPs that
    # tighter per-model calibration would otherwise suppress solo.
    _ENSEMBLE_TRIPLE_EXTRA = 0.12

    # Entity categories where partial detectors (e.g. multilingual GLiNER
    # on English) are allowed to cast a 0.5x vote instead of being fully
    # excluded.  These are categories where the multilingual model adds
    # unique value (non-Western names, international locations).
    _PARTIAL_VOTE_CATEGORIES = frozenset({
        "names", "locations",
    })
    _PARTIAL_VOTE_WEIGHT = 0.5

    def _apply_ensemble_boost(
        self,
        spans: list[Span],
        excluded_detectors: frozenset[str] = frozenset(),
        partial_detectors: frozenset[str] = frozenset(),
    ) -> list[Span]:
        """Boost confidence when multiple detectors agree on the same entity.

        For each span, checks if different detectors produced overlapping
        spans with a compatible entity type (same evaluation category, e.g.
        FIRSTNAME and NAME are both "names").

        Boost scales with agreement strength:
        - 2 detectors agree: base boost (0.10–0.20)
        - 3+ detectors agree: base boost + triple bonus (0.08)

        The base boost scales with the minimum raw confidence of the agreeing
        pair — strong agreement earns up to ``_ENSEMBLE_BOOST_MAX``, while
        marginal agreement earns ``_ENSEMBLE_BOOST_MIN``.

        Args:
            excluded_detectors: Detector names that do not count for voting.
                Their spans still receive boosts from other detectors, but
                they cannot *contribute* to the agreement count.  This gates
                noisy duplicates (e.g. multilingual GLiNER on English text)
                from inflating ensemble confidence.
            partial_detectors: Detector names that get partial voting weight
                (0.5x) for name/location categories.  On other categories
                they remain fully excluded.  This lets the multilingual
                GLiNER contribute to agreement for non-Western names while
                still being gated for other entity types.
        """
        if len(spans) < 2:
            return spans

        from bisect import bisect_left
        from ..benchmark.entity_mapping import EVAL_CATEGORIES

        def _entity_group(entity_type: str) -> str:
            """Return the category group for an entity type, or its normalized form."""
            norm = normalize_entity_type(entity_type)
            return EVAL_CATEGORIES.get(norm, norm)

        boosted_indices: set[int] = set()
        result = list(spans)

        # Build a position-based index to avoid O(n^2) all-pairs comparison.
        # Sort span indices by start position; for each span_a we only need to
        # check spans whose start < span_a.end (necessary for overlap).
        sorted_indices = sorted(range(len(spans)), key=lambda k: spans[k].start)
        sorted_starts = [spans[k].start for k in sorted_indices]

        for i, span_a in enumerate(spans):
            if i in boosted_indices:
                continue
            group_a = _entity_group(span_a.entity_type)

            # Collect all agreeing detectors for this span.
            # Excluded detectors do NOT count toward agreement unless
            # they are partial detectors and the category allows it.
            agreeing_weight: float = 0.0
            agreeing_detectors: set[str] = set()
            min_raw = 1.0

            # Find the range of spans that could overlap with span_a.
            # A span_b overlaps span_a iff span_b.start < span_a.end
            # AND span_a.start < span_b.end.  We use the sorted index
            # to limit candidates to those with start < span_a.end.
            right_bound = bisect_left(sorted_starts, span_a.end)
            for idx in range(right_bound):
                j = sorted_indices[idx]
                if i == j or span_a.detector == spans[j].detector:
                    continue
                span_b = spans[j]
                # Second half of the overlap check (sorted index
                # already guarantees span_b.start < span_a.end).
                if span_a.start >= span_b.end:
                    continue
                if span_b.detector in excluded_detectors:
                    # Check if this is a partial detector for this category
                    if (
                        span_b.detector in partial_detectors
                        and group_a in self._PARTIAL_VOTE_CATEGORIES
                    ):
                        # Partial vote: counts as 0.5x weight
                        group_b = _entity_group(span_b.entity_type)
                        if group_a != group_b:
                            continue
                        agreeing_detectors.add(span_b.detector)
                        agreeing_weight += self._PARTIAL_VOTE_WEIGHT
                        raw_b = span_b.raw_confidence if span_b.raw_confidence is not None else span_b.confidence
                        min_raw = min(min_raw, raw_b)
                    continue
                group_b = _entity_group(span_b.entity_type)
                if group_a != group_b:
                    continue
                agreeing_detectors.add(span_b.detector)
                agreeing_weight += 1.0
                raw_b = span_b.raw_confidence if span_b.raw_confidence is not None else span_b.confidence
                min_raw = min(min_raw, raw_b)

            if not agreeing_detectors:
                continue

            raw_a = span_a.raw_confidence if span_a.raw_confidence is not None else span_a.confidence
            min_raw = min(min_raw, raw_a)

            # Scale base boost by minimum raw confidence.
            t = max(0.0, min(1.0, (min_raw - 0.5) / 0.4))
            boost = self._ENSEMBLE_BOOST_MIN + t * (self._ENSEMBLE_BOOST_MAX - self._ENSEMBLE_BOOST_MIN)

            # Triple-agreement bonus: effective agreement ≥ 3 (counting
            # partial weights).  span_a counts toward the total only if
            # it is not excluded.
            span_a_weight = (
                self._PARTIAL_VOTE_WEIGHT
                if span_a.detector in partial_detectors
                and group_a in self._PARTIAL_VOTE_CATEGORIES
                else (0.0 if span_a.detector in excluded_detectors else 1.0)
            )
            n_agree = agreeing_weight + span_a_weight
            if n_agree >= 3.0:
                boost += self._ENSEMBLE_TRIPLE_EXTRA

            new_conf = min(1.0, span_a.confidence + boost)
            result[i] = Span(
                start=span_a.start,
                end=span_a.end,
                text=span_a.text,
                entity_type=span_a.entity_type,
                confidence=new_conf,
                detector=span_a.detector,
                tier=span_a.tier,
                context=span_a.context,
                needs_review=span_a.needs_review,
                review_reason=span_a.review_reason,
                coref_anchor_value=span_a.coref_anchor_value,
                raw_confidence=span_a.raw_confidence,
                detector_label=span_a.detector_label,
            )
            boosted_indices.add(i)
            logger.debug(
                "Ensemble boost: %s@%d-%d %.3f->%.3f (+%.3f, %.1f effective detectors: %s)",
                span_a.entity_type, span_a.start, span_a.end,
                span_a.confidence, new_conf, boost, n_agree,
                ", ".join(sorted(agreeing_detectors)),
            )

        return result

    def add_detector(self, detector: BaseDetector) -> None:
        """Add a custom detector to the orchestrator."""
        self.detectors.append(detector)
        logger.info(f"Added detector: {detector.name}")

    def remove_detector(self, name: str) -> bool:
        """Remove a detector by name."""
        for i, detector in enumerate(self.detectors):
            if detector.name == name:
                self.detectors.pop(i)
                logger.info(f"Removed detector: {name}")
                return True
        return False


def detect(
    text: str,
    config: DetectionConfig | None = None,
    **kwargs: object,
) -> DetectionResult:
    """Detect entities in text using a one-shot orchestrator."""
    if config is None:
        from dataclasses import fields as dc_fields
        config_kwargs = {
            k: v for k, v in kwargs.items()
            if k in {f.name for f in dc_fields(DetectionConfig)}
        }
        config = DetectionConfig(**config_kwargs)  # type: ignore[arg-type]

    orchestrator = DetectorOrchestrator(config=config)
    return orchestrator.detect_sync(text)
