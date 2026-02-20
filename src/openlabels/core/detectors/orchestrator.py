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
from .registry import create_detector

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

        logger.info(
            f"DetectorOrchestrator initialized with {len(self.detectors)} detectors: "
            f"{[d.name for d in self.detectors]}"
            f"{' (Hyperscan accelerated)' if self._using_hyperscan else ''}"
        )

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

        processed_spans = self._post_process(all_spans, text=text)

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

    # Ensemble boost amount when 2+ detectors agree on the same span.
    _ENSEMBLE_BOOST = 0.15

    def _post_process(
        self,
        spans: list[Span],
        text: str | None = None,
    ) -> list[Span]:
        """Post-process: filter, context-adjust, calibrate, ensemble, deduplicate.

        Pipeline order:
        1. Filter by per-entity / per-tier raw confidence threshold
        2. Apply context keyword boost/demote (on raw confidence)
        3. Calibrate into unified tier bands
        4. Ensemble boost (when 2+ detectors agree)
        5. Resolve overlapping spans
        6. Suppress uncorroborated ML detections for pattern-covered types
        7. Proximity boost (optional)
        """
        filtered = [s for s in spans if self._passes_threshold(s)]

        # Context keyword adjustment (before calibration)
        if self.config.enable_context_keywords and text and filtered:
            from ..pipeline.context_keywords import apply_context_keywords
            filtered = apply_context_keywords(filtered, text)

        calibrated = calibrate_spans(filtered)

        # Ensemble boost: when multiple detectors agree on overlapping
        # spans with the same entity type, boost the best span's confidence.
        calibrated = self._apply_ensemble_boost(calibrated)

        from ..pipeline.span_resolver import OverlapStrategy

        resolved = resolve_spans(
            calibrated,
            confidence_threshold=0.0,
            strategy=OverlapStrategy.HIGHER_TIER,
            source_text=text,
        )

        # Suppress uncorroborated ML detections: ML spans for entity types
        # that patterns handle well (dates, addresses, financial, etc.) are
        # suppressed unless they were ensemble-boosted or have high confidence.
        # ML should primarily contribute names and rare professional
        # entities — things patterns cannot detect.
        resolved = _suppress_uncorroborated_ml(resolved, calibrated)

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

    def _apply_ensemble_boost(self, spans: list[Span]) -> list[Span]:
        """Boost confidence when multiple detectors agree on the same entity.

        For each span, checks if a different detector produced an overlapping
        span with a compatible entity type (same evaluation category, e.g.
        FIRSTNAME and NAME are both "names").  If so, the higher-confidence
        span gets boosted (clamped to 1.0).

        This rewards multi-detector agreement without adding new detections.
        """
        if len(spans) < 2:
            return spans

        from ..benchmark.entity_mapping import EVAL_CATEGORIES

        def _entity_group(entity_type: str) -> str:
            """Return the category group for an entity type, or its normalized form."""
            norm = normalize_entity_type(entity_type)
            return EVAL_CATEGORIES.get(norm, norm)

        boosted_indices: set[int] = set()
        result = list(spans)

        for i, span_a in enumerate(spans):
            if i in boosted_indices:
                continue
            group_a = _entity_group(span_a.entity_type)
            for j, span_b in enumerate(spans):
                if i == j or span_a.detector == span_b.detector:
                    continue
                if not span_a.overlaps(span_b):
                    continue
                group_b = _entity_group(span_b.entity_type)
                if group_a != group_b:
                    continue
                # Two different detectors agree — boost the stronger one.
                if i not in boosted_indices:
                    new_conf = min(1.0, span_a.confidence + self._ENSEMBLE_BOOST)
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
                    )
                    boosted_indices.add(i)
                    logger.debug(
                        "Ensemble boost: %s %r %.3f→%.3f (corroborated by %s)",
                        span_a.entity_type, span_a.text,
                        span_a.confidence, new_conf, span_b.detector,
                    )
                break  # Only boost once per span

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

    @property
    def detector_names(self) -> list[str]:
        """Get list of active detector names."""
        return [d.name for d in self.detectors]


# ---------------------------------------------------------------------------
# ML corroboration filter
# ---------------------------------------------------------------------------

# Entity types where ML adds unique value (patterns cannot detect them).
# ML spans for these types survive unconditionally after dedup.
_ML_PRIMARY_TYPES = frozenset({
    # Names: the main reason ML exists in the pipeline
    "NAME", "FIRSTNAME", "LASTNAME", "MIDDLENAME",
    "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    "PERSON", "PATIENT", "FULLNAME",
    # Professional: keep only types with zero pattern coverage.
    # COMPANY and JOB_TITLE removed — they generate too many FPs and
    # should be held to the corroboration / uncorroborated-confidence
    # bar instead.  EMPLOYER has keyword-context patterns that
    # corroborate well; EMPLOYEE_ID / FACILITY are rare enough to keep.
    "EMPLOYER", "EMPLOYEE_ID", "FACILITY",
    # Medical identifiers: benefit from ML context
    "MRN", "HEALTH_PLAN_ID", "NPI", "MEDICAL_LICENSE",
    # Age: patterns miss natural-language age references
    "AGE",
})

# Minimum calibrated confidence for ML-only spans on types where
# patterns are the primary detector.  Below this, the ML detection
# is too uncertain to trust without pattern corroboration.
# At 0.52, an ML span needs raw confidence ≥ 0.88 to survive
# without any pattern backup (calibrated ML range is [0.30, 0.55]).
_ML_UNCORROBORATED_MIN = 0.52

# Types that ALWAYS require pattern corroboration, regardless of
# confidence.  These are known false-positive generators — even
# high-confidence ML detections are unreliable without a pattern echo.
_STRICT_CORROBORATION_TYPES = frozenset({"COMPANY", "JOB_TITLE"})

# Minimum calibrated confidence for ML-primary spans (names, etc.)
# to survive *without* any corroboration from another detector.
# Below this, at least one other detector (pattern or a different ML
# model) must agree on an overlapping same-group span.  This catches
# borderline single-detector name hallucinations while preserving
# high-confidence or multi-detector-agreed detections.
# At 0.44, GLiNER names need raw ≥ 0.56 to stand alone.
_ML_PRIMARY_SOLO_MIN = 0.44

# Broad groups for corroboration matching.  A pattern span only
# corroborates an ML span if they share the same group.  This prevents
# e.g. an ADDRESS pattern from falsely corroborating a COMPANY ML span
# just because they overlap positionally.  Types not listed here each
# get their own unique group (i.e. only corroborate same-type spans).
_CORROBORATION_GROUP: dict[str, str] = {
    # Names
    "NAME": "names", "FIRSTNAME": "names", "LASTNAME": "names",
    "MIDDLENAME": "names", "PREFIX": "names", "SUFFIX": "names",
    "PERSON": "names", "FULLNAME": "names", "PATIENT": "names",
    "NAME_PATIENT": "names", "NAME_PROVIDER": "names",
    "NAME_RELATIVE": "names",
    # Professional
    "COMPANY": "professional", "EMPLOYER": "professional",
    "JOB_TITLE": "professional", "FACILITY": "professional",
    "EMPLOYEE_ID": "professional",
    # Locations
    "ADDRESS": "locations", "CITY": "locations", "STATE": "locations",
    "COUNTY": "locations", "COUNTRY": "locations", "ZIP": "locations",
    "GPS_COORDINATE": "locations", "GPS_COORDINATES": "locations",
    # Financial
    "CREDIT_CARD": "financial", "IBAN": "financial",
    "SWIFT_BIC": "financial", "ACCOUNT_NUMBER": "financial",
    "BANK_ROUTING": "financial", "ABA_ROUTING": "financial",
    # Contact
    "EMAIL": "contact", "PHONE": "contact", "URL": "contact",
    "USERNAME": "contact", "FAX": "contact",
    # Dates
    "DATE": "dates", "DATE_DOB": "dates", "TIME": "dates",
    "DATETIME": "dates", "AGE": "dates",
    # Government IDs
    "SSN": "gov_ids", "DRIVER_LICENSE": "gov_ids",
    "PASSPORT": "gov_ids", "STATE_ID": "gov_ids", "TAX_ID": "gov_ids",
    # Network
    "IP_ADDRESS": "network", "MAC_ADDRESS": "network", "IMEI": "network",
    # Secrets
    "PASSWORD": "secrets", "API_KEY": "secrets", "SECRET": "secrets",
    "PRIVATE_KEY": "secrets", "JWT": "secrets",
}


def _corroboration_group(entity_type: str) -> str:
    """Return the corroboration group for an entity type.

    Types in the same group can corroborate each other.  Types not
    in the mapping get their own unique group (the type name itself).
    """
    return _CORROBORATION_GROUP.get(entity_type, entity_type)


def _suppress_uncorroborated_ml(
    resolved: list[Span],
    all_calibrated: list[Span],
) -> list[Span]:
    """Suppress ML-only detections that lack corroboration.

    Three-tier suppression logic, from strictest to most permissive:

    1. **Strict-corroboration types** (COMPANY, JOB_TITLE): always
       suppressed unless a pattern detector in the same category fired
       at the same position.  These types are prolific FP generators.

    2. **Non-ML-primary types** (dates, locations, financial, …): kept
       if corroborated by a same-group pattern, or if calibrated
       confidence ≥ ``_ML_UNCORROBORATED_MIN``.

    3. **ML-primary types** (names, employers, …): kept unconditionally
       when calibrated confidence ≥ ``_ML_PRIMARY_SOLO_MIN``.  Below
       that threshold, at least one *other* detector (pattern or a
       different ML model) must produce an overlapping same-group span.
       This catches borderline single-model name hallucinations.
    """
    if not resolved:
        return resolved

    # Collect character ranges and groups covered by non-ML spans (before dedup).
    pattern_ranges: list[tuple[int, int, str]] = []
    for s in all_calibrated:
        if s.tier != Tier.ML:
            ptype = normalize_entity_type(s.entity_type)
            pattern_ranges.append((s.start, s.end, _corroboration_group(ptype)))

    result: list[Span] = []
    for span in resolved:
        if span.tier != Tier.ML:
            result.append(span)
            continue

        etype = normalize_entity_type(span.entity_type)
        ml_group = _corroboration_group(etype)

        # ── 1. Strict-corroboration types ──────────────────────────
        if etype in _STRICT_CORROBORATION_TYPES:
            corroborated = any(
                _ranges_overlap(span.start, span.end, ps, pe)
                and pg == ml_group
                for ps, pe, pg in pattern_ranges
            )
            if corroborated:
                result.append(span)
            else:
                logger.debug(
                    "ML suppressed (strict): %s %r conf=%.3f",
                    span.entity_type, span.text, span.confidence,
                )
            continue

        # ── 2. ML-primary types ────────────────────────────────────
        if etype in _ML_PRIMARY_TYPES:
            # High confidence: keep unconditionally
            if span.confidence >= _ML_PRIMARY_SOLO_MIN:
                result.append(span)
                continue
            # Low confidence: require any same-group agreement from
            # another detector (pattern tier OR a different ML model).
            any_agreement = any(
                _ranges_overlap(span.start, span.end, s.start, s.end)
                and _corroboration_group(normalize_entity_type(s.entity_type)) == ml_group
                and s.detector != span.detector
                for s in all_calibrated
            )
            if any_agreement:
                result.append(span)
            else:
                logger.debug(
                    "ML suppressed (primary, solo low-conf): %s %r conf=%.3f",
                    span.entity_type, span.text, span.confidence,
                )
            continue

        # ── 3. Non-ML-primary types ────────────────────────────────
        corroborated = any(
            _ranges_overlap(span.start, span.end, ps, pe)
            and pg == ml_group
            for ps, pe, pg in pattern_ranges
        )
        if corroborated:
            result.append(span)
            continue

        if span.confidence >= _ML_UNCORROBORATED_MIN:
            result.append(span)
        else:
            logger.debug(
                "ML suppressed (uncorroborated): %s %r conf=%.3f",
                span.entity_type, span.text, span.confidence,
            )

    return result


def _ranges_overlap(s1: int, e1: int, s2: int, e2: int) -> bool:
    """Return True if two character ranges overlap at all."""
    return s1 < e2 and s2 < e1


# ---------------------------------------------------------------------------
# Pronoun suppression
# ---------------------------------------------------------------------------

# NAME-family types that can be false-positively assigned to pronouns.
_NAME_FAMILY = frozenset({
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    "FIRSTNAME", "LASTNAME",
})

# Personal pronouns (lower-cased) that are never PII by themselves.
# Covers English + the 8 other multilingual-supported languages.
_PRONOUNS = frozenset({
    # English
    "he", "him", "his", "she", "her", "hers",
    "they", "them", "their", "theirs",
    # Spanish
    "él", "ella", "ellos", "ellas",
    # French
    "il", "elle", "ils", "elles", "lui",
    # Portuguese
    "ele", "ela", "eles", "elas",
    # German
    "er", "sie", "es", "ihr", "ihm", "ihn",
    # Italian
    "egli", "essa", "esso", "loro",
    # Dutch
    "hij", "zij", "hen", "hun",
    # Greek
    "αυτός", "αυτή", "αυτό", "αυτοί", "αυτές", "αυτά",
})


def _suppress_pronoun_names(spans: list[Span]) -> list[Span]:
    """Remove NAME-family spans whose text is just a pronoun."""
    result: list[Span] = []
    for span in spans:
        if span.entity_type in _NAME_FAMILY and span.text.strip().lower() in _PRONOUNS:
            logger.debug("Pronoun suppressed: %s %r", span.entity_type, span.text)
            continue
        result.append(span)
    return result


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
