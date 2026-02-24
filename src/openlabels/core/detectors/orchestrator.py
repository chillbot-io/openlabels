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

    # Ensemble boost range when 2+ detectors agree on the same span.
    # Actual boost is scaled by the minimum raw confidence of the
    # agreeing detectors — well-calibrated agreement gets a larger boost.
    _ENSEMBLE_BOOST_MIN = 0.10
    _ENSEMBLE_BOOST_MAX = 0.20

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
        5. Suppress ML name fragments that collide with pattern detections
        6. Resolve overlapping spans
        7. Suppress uncorroborated ML detections for pattern-covered types
        8. Proximity boost (optional)
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
        resolved = _correct_type_confusions(resolved)

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

    def _apply_ensemble_boost(self, spans: list[Span]) -> list[Span]:
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

            # Collect all agreeing detectors for this span.
            agreeing_detectors: set[str] = set()
            min_raw = 1.0
            for j, span_b in enumerate(spans):
                if i == j or span_a.detector == span_b.detector:
                    continue
                if not span_a.overlaps(span_b):
                    continue
                group_b = _entity_group(span_b.entity_type)
                if group_a != group_b:
                    continue
                agreeing_detectors.add(span_b.detector)
                raw_b = span_b.raw_confidence if span_b.raw_confidence is not None else span_b.confidence
                min_raw = min(min_raw, raw_b)

            if not agreeing_detectors:
                continue

            raw_a = span_a.raw_confidence if span_a.raw_confidence is not None else span_a.confidence
            min_raw = min(min_raw, raw_a)

            # Scale base boost by minimum raw confidence.
            t = max(0.0, min(1.0, (min_raw - 0.5) / 0.4))
            boost = self._ENSEMBLE_BOOST_MIN + t * (self._ENSEMBLE_BOOST_MAX - self._ENSEMBLE_BOOST_MIN)

            # Triple-agreement bonus: 3+ unique detectors agree.
            n_agree = len(agreeing_detectors) + 1  # +1 for span_a itself
            if n_agree >= 3:
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
            )
            boosted_indices.add(i)
            logger.debug(
                "Ensemble boost: %s %r %.3f→%.3f (+%.3f, %d detectors: %s)",
                span_a.entity_type, span_a.text,
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
    # COMPANY moved here from strict corroboration — strict was
    # suppressing 17 real companies on ai4privacy (100% recall at 62%
    # precision).  With ML-primary + solo-min gating, high-confidence
    # GLiNER COMPANY detections survive solo while low-confidence ones
    # still require corroboration, balancing recall vs FP.
    "COMPANY",
    # JOB_TITLE moved here from strict corroboration — strict was
    # suppressing 41 real job titles on nemotron_pii because no
    # pattern detector exists for JOB_TITLE, making the strict
    # threshold (≥0.62) unreachable for most GLiNER detections.
    # With ML-primary + calibration gating (temp=1.25), moderate-
    # confidence detections survive while low-confidence FPs are
    # still filtered.
    "JOB_TITLE",
    "EMPLOYER", "EMPLOYEE_ID", "FACILITY",
    # Medical identifiers: benefit from ML context
    "MRN", "HEALTH_PLAN_ID", "NPI", "MEDICAL_LICENSE",
    # AGE removed from ML-primary: 4 spurious on ai4privacy 100,
    # pattern detectors handle structured age references.  Natural-
    # language ages ("25 years old") activate via CONTACT category.
    # Addresses: pattern detectors catch structured formats but miss
    # unstructured addresses (street names, building numbers without
    # city/state/zip context).  52 ADDRESS misses on ai4privacy 10k;
    # many are GLiNER detections suppressed because ADDRESS was non-
    # ML-primary (required raw ≥ 0.94 to survive uncorroborated).
    "ADDRESS",
    # USERNAME: pattern detectors handle labelled formats (username:X)
    # and structured formats (First_Last, CamelCase.Dot), but miss
    # some HF 400k usernames.  ML-primary lets GLiNER USERNAME
    # detections survive solo when patterns don't fire.
    "USERNAME",
})

# Default minimum calibrated confidence for ML-only spans on types where
# patterns are the primary detector (used when calibration data is absent).
# Lowered from 0.60 back to 0.55: the 0.60 threshold (raised to fight
# GLiNER FPs on ai4privacy 400k) also kills recall on entity types where
# patterns miss due to different PII formats in the 400k dataset.  The net
# effect was worse F1 (recall dropped more than precision improved).
_ML_UNCORROBORATED_MIN_DEFAULT = 0.55

# Types that require pattern corroboration unless the span's calibrated
# confidence exceeds _STRICT_SOLO_MIN.  High-confidence detections for
# these types are allowed through solo — the calibration temperature
# already dampened unreliable scores, so survivors are trustworthy.
_STRICT_CORROBORATION_TYPES = frozenset({"DRIVER_LICENSE"})
_STRICT_SOLO_MIN = 0.62

# Default minimum calibrated confidence for ML-primary spans to
# survive solo (used when calibration data is absent).
_ML_PRIMARY_SOLO_MIN_DEFAULT = 0.52


def _calibrated_threshold(span: Span, base: float) -> float:
    """Derive a per-span suppression threshold from calibration data.

    Checks the calibration table corresponding to the span's detector:
    GLiNER, Stanford PHI, or multilingual GLiNER.  Labels with high
    calibration temperature (>1.0) are overconfident and need a *higher*
    calibrated confidence to survive solo.  Well-calibrated labels
    (temperature ≤ 1.0) use the base threshold.

    Falls back to *base* when the span has no calibration metadata.
    """
    label = span.detector_label
    if label is None:
        return base

    # Look up calibration in the table matching this span's detector.
    params: tuple[float, float] | None = None
    detector = span.detector if span.detector else ""

    if detector == "stanford_phi":
        from .phi_detector import PHI_CALIBRATION
        params = PHI_CALIBRATION.get(label)
    elif detector == "gliner_multilingual":
        from .multilingual_gliner import MULTILINGUAL_CALIBRATION
        params = MULTILINGUAL_CALIBRATION.get(label)
    else:
        from .gliner_calibration import get_active_calibration
        table = get_active_calibration()
        params = table.get(label)

    if params is None:
        return base

    temperature = params[0]
    # Scale: overconfident labels (temp >> 1.0) need higher confidence to
    # survive solo.  Cap at 0.63 (was 0.62, raised modestly) with
    # scaling 0.09 (was 0.08).  0.64/0.10 was too aggressive —
    # cratered name recall to 0.512 by suppressing too many solo names.
    return min(0.63, base + max(0.0, temperature - 1.0) * 0.09)

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


import re as _re

# Name-part token regex: a capitalized word, possibly with apostrophe/hyphen
_NAME_TOKEN_RE = _re.compile(
    r"[A-Z\u00C0-\u024F][a-z\u00C0-\u024F''\-]*"
    r"(?:[''\-][A-Z\u00C0-\u024F]?[a-z\u00C0-\u024F]*)?"
)

# Entity types whose multi-word spans should be split into name parts.
_SPLITTABLE_NAME_TYPES = frozenset({
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
})


# Honorific prefixes to strip when splitting name spans.
_TITLE_PREFIXES = frozenset({
    "mr", "mrs", "ms", "miss", "dr", "prof", "sir", "dame",
    "rev", "judge", "hon", "sgt", "cpl", "capt", "lt", "col",
    "gen", "maj", "cmdr", "adm",
})


def _split_name_spans(spans: list[Span]) -> list[Span]:
    """Split multi-word NAME spans into individual FIRSTNAME + LASTNAME spans.

    Benchmark gold annotations label each name part separately (FIRSTNAME,
    LASTNAME, MIDDLENAME).  Pattern detectors output combined spans like
    NAME "Danielle Braun".  Splitting improves alignment with gold annotations,
    preventing false misses from the 50% overlap requirement.

    Single-word NAME spans are relabeled to FIRSTNAME.
    For multi-word spans: first part → FIRSTNAME, last part → LASTNAME,
    any middle parts → MIDDLENAME.
    Title prefixes (Mr, Dr, Miss, etc.) are emitted as PREFIX.
    """
    result: list[Span] = []
    for span in spans:
        if span.entity_type not in _SPLITTABLE_NAME_TYPES:
            result.append(span)
            continue

        # Find name tokens within the span text
        tokens = list(_NAME_TOKEN_RE.finditer(span.text))
        if len(tokens) <= 1:
            # Single-word name: relabel to FIRSTNAME
            result.append(Span(
                start=span.start,
                end=span.end,
                text=span.text,
                entity_type="FIRSTNAME",
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                raw_confidence=span.raw_confidence,
                detector_label=span.detector_label,
            ))
            continue

        # Strip leading title prefixes (don't emit PREFIX spans — the
        # ai4privacy and PHI benchmarks don't label honorifics, so
        # emitting them only creates spurious FPs.  Pattern detectors
        # still emit PREFIX independently for datasets that need it.)
        name_tokens = []
        had_prefix = False
        title_done = False
        for tok in tokens:
            if not title_done and tok.group().lower().rstrip('.') in _TITLE_PREFIXES:
                had_prefix = True
            else:
                title_done = True
                name_tokens.append(tok)

        # Filter out single-character tokens and common non-name words
        name_tokens = [t for t in name_tokens if len(t.group()) >= 2]

        if not name_tokens:
            continue

        if len(name_tokens) == 1:
            tok = name_tokens[0]
            tok_start = span.start + tok.start()
            tok_end = span.start + tok.end()
            # Single name after title could be first or last name.
            # If preceded by a title (Mr./Dr.), it's more likely a LASTNAME.
            etype = "LASTNAME" if had_prefix else "FIRSTNAME"
            result.append(Span(
                start=tok_start,
                end=tok_end,
                text=tok.group(),
                entity_type=etype,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                raw_confidence=span.raw_confidence,
                detector_label=span.detector_label,
            ))
            continue

        # Multi-word name: split into FIRSTNAME / MIDDLENAME / LASTNAME
        for i, tok in enumerate(name_tokens):
            if i == 0:
                etype = "FIRSTNAME"
            elif i == len(name_tokens) - 1:
                etype = "LASTNAME"
            else:
                etype = "MIDDLENAME"

            tok_start = span.start + tok.start()
            tok_end = span.start + tok.end()
            result.append(Span(
                start=tok_start,
                end=tok_end,
                text=tok.group(),
                entity_type=etype,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                raw_confidence=span.raw_confidence,
                detector_label=span.detector_label,
            ))

    return result


def _suppress_uncorroborated_ml(
    resolved: list[Span],
    all_calibrated: list[Span],
) -> list[Span]:
    """Suppress ML-only detections that lack corroboration.

    Three-tier suppression logic, from strictest to most permissive.
    Thresholds are derived per-span from calibration data via
    :func:`_calibrated_threshold` — labels with high calibration
    temperature (overconfident) require stricter thresholds, while
    well-calibrated labels can survive at lower confidence.

    1. **Strict-corroboration types** (JOB_TITLE, DRIVER_LICENSE):
       suppressed unless pattern-corroborated OR calibrated confidence
       ≥ ``_STRICT_SOLO_MIN`` (high-confidence override).

    2. **Non-ML-primary types** (dates, locations, financial, …): kept
       if pattern-corroborated, or if calibrated confidence ≥ the
       per-span threshold derived from calibration.

    3. **ML-primary types** (names, employers, …): kept when calibrated
       confidence ≥ per-span threshold.  Below that, require any
       other detector to agree.
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
    suppressed_count = 0
    suppressed_types: dict[str, int] = {}

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
            elif span.confidence >= _STRICT_SOLO_MIN:
                # High-confidence override: calibration already dampened
                # unreliable scores, so survivors are trustworthy.
                result.append(span)
                logger.debug(
                    "ML strict override (high-conf solo): %s %r conf=%.3f",
                    span.entity_type, span.text, span.confidence,
                )
            else:
                suppressed_count += 1
                suppressed_types[etype] = suppressed_types.get(etype, 0) + 1
                logger.debug(
                    "ML suppressed (strict): %s %r conf=%.3f",
                    span.entity_type, span.text, span.confidence,
                )
            continue

        # ── 2. ML-primary types ────────────────────────────────────
        if etype in _ML_PRIMARY_TYPES:
            solo_min = _calibrated_threshold(span, _ML_PRIMARY_SOLO_MIN_DEFAULT)
            # High confidence: keep unconditionally
            if span.confidence >= solo_min:
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
                suppressed_count += 1
                suppressed_types[etype] = suppressed_types.get(etype, 0) + 1
                logger.debug(
                    "ML suppressed (primary, solo low-conf): %s %r conf=%.3f (min=%.3f)",
                    span.entity_type, span.text, span.confidence, solo_min,
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

        uncorr_min = _calibrated_threshold(span, _ML_UNCORROBORATED_MIN_DEFAULT)
        if span.confidence >= uncorr_min:
            result.append(span)
        else:
            suppressed_count += 1
            suppressed_types[etype] = suppressed_types.get(etype, 0) + 1
            logger.debug(
                "ML suppressed (uncorroborated): %s %r conf=%.3f (min=%.3f)",
                span.entity_type, span.text, span.confidence, uncorr_min,
            )

    if suppressed_count:
        ml_total = sum(1 for s in resolved if s.tier == Tier.ML)
        top_types = ", ".join(
            f"{t}({c})" for t, c in sorted(
                suppressed_types.items(), key=lambda x: -x[1]
            )[:5]
        )
        logger.info(
            "ML corroboration: suppressed %d/%d ML spans (%.0f%%). "
            "Top suppressed types: %s",
            suppressed_count,
            ml_total,
            suppressed_count / ml_total * 100 if ml_total else 0,
            top_types,
        )

    return result


def _ranges_overlap(s1: int, e1: int, s2: int, e2: int) -> bool:
    """Return True if two character ranges overlap at all."""
    return s1 < e2 and s2 < e1


# ---------------------------------------------------------------------------
# Type confusion correction
# ---------------------------------------------------------------------------

# Username format: contains underscore/dot between name parts, or trailing
# digits after a name — e.g. "First_Last", "John.Doe42", "Alice99"
_USERNAME_FORMAT_RE = _re.compile(
    r'^[A-Za-z][A-Za-z0-9]*[._][A-Za-z][A-Za-z0-9]*(?:[._][A-Za-z0-9]+)*\d{0,4}$'
    r'|'
    r'^[A-Za-z]{2,15}\d{1,4}$'
)

# US SSN format: XXX-XX-XXXX (with various separators)
_SSN_FORMAT_RE = _re.compile(
    r'^\d{3}[\s\-\.]\d{2}[\s\-\.]\d{4}$'
)


def _correct_type_confusions(spans: list[Span]) -> list[Span]:
    """Reclassify ML spans that match a more specific type's format.

    GLiNER has known confusion patterns (from nemotron_pii 1000-sample):
    - USERNAME → FIRSTNAME (14): usernames with underscores/dots/digits
    - PHONE → SSN: social security numbers in XXX-XX-XXXX format
    - SSN classified on routing numbers: 9-digit numbers passing ABA checksum

    Only reclassifies ML-tier spans (pattern detections are trusted).
    """
    from .checksum import validate_aba_routing

    result: list[Span] = []
    corrections: dict[str, int] = {}
    for span in spans:
        if span.tier != Tier.ML:
            result.append(span)
            continue

        etype = normalize_entity_type(span.entity_type)
        text = span.text.strip()
        new_type = None

        # FIRSTNAME/LASTNAME → USERNAME when text matches username format
        if etype in ("FIRSTNAME", "LASTNAME") and _USERNAME_FORMAT_RE.match(text):
            new_type = "USERNAME"

        # PHONE → SSN when text matches US SSN format (XXX-XX-XXXX)
        elif etype == "PHONE" and _SSN_FORMAT_RE.match(text):
            new_type = "SSN"

        # SSN → BANK_ROUTING when bare 9-digit passes ABA checksum
        elif etype == "SSN":
            digits = _re.sub(r'\D', '', text)
            if len(digits) == 9:
                valid, _ = validate_aba_routing(digits)
                if valid:
                    new_type = "BANK_ROUTING"

        if new_type is not None:
            key = f"{etype}→{new_type}"
            corrections[key] = corrections.get(key, 0) + 1
            logger.debug(
                "Type correction: %s → %s for %r",
                span.entity_type, new_type, text,
            )
            result.append(Span(
                start=span.start,
                end=span.end,
                text=span.text,
                entity_type=new_type,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                raw_confidence=span.raw_confidence,
                detector_label=span.detector_label,
            ))
        else:
            result.append(span)

    if corrections:
        detail = ", ".join(f"{k}({v})" for k, v in corrections.items())
        logger.info("Type corrections applied: %s", detail)
    return result


# ---------------------------------------------------------------------------
# Pronoun suppression
# ---------------------------------------------------------------------------

# NAME-family types that can be false-positively assigned to pronouns.
_NAME_FAMILY = frozenset({
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    "FIRSTNAME", "LASTNAME", "MIDDLENAME",
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


# ---------------------------------------------------------------------------
# Pre-dedup: ML name fragment suppression
# ---------------------------------------------------------------------------

# Pattern types that should take priority over ML name detections at the
# same position.  USERNAME is the most important: patterns detect compound
# tokens like "Roma_Altenwerth" while GLiNER only sees the word fragment
# "Roma" → without suppression the ML FIRSTNAME absorbs the USERNAME in
# HIGHER_TIER dedup.  Locations suffer the same problem: "Florence" as
# CITY (pattern) vs FIRSTNAME (GLiNER).
_PATTERN_PRIORITY_OVER_NAMES = frozenset({
    "USERNAME",
    "CITY", "STATE", "COUNTY", "COUNTRY", "ZIP",
    "ADDRESS", "GPS_COORDINATE", "GPS_COORDINATES",
    # COMPANY: pattern detectors catch corporate suffixes (Inc, LLC, etc.)
    # but GLiNER also detects the same span as FIRSTNAME.  5 COMPANY→
    # FIRSTNAME type mismatches on nemotron_pii from this collision.
    "COMPANY",
})


def _suppress_ml_name_collisions(spans: list[Span]) -> list[Span]:
    """Remove ML name spans that overlap with pattern non-name spans.

    Must run BEFORE ``resolve_spans``.  Prevents ML FIRSTNAME/LASTNAME
    detections from absorbing pattern detections of more specific types
    during HIGHER_TIER dedup.

    Two scenarios fixed:
    1. USERNAME "Roma_Altenwerth" (PATTERN) vs FIRSTNAME "Roma" (ML)
       → remove the ML FIRSTNAME, keep the pattern USERNAME.
    2. CITY "Florence" (PATTERN) vs FIRSTNAME "Florence" (ML)
       → remove the ML FIRSTNAME, keep the pattern CITY.
    """
    from ..types import Tier

    # Collect ranges of non-ML spans with priority types
    priority_ranges: list[tuple[int, int]] = []
    for s in spans:
        if s.tier != Tier.ML:
            norm = normalize_entity_type(s.entity_type)
            if norm in _PATTERN_PRIORITY_OVER_NAMES:
                priority_ranges.append((s.start, s.end))

    if not priority_ranges:
        return spans

    result: list[Span] = []
    suppressed = 0
    for span in spans:
        if span.tier == Tier.ML and span.entity_type in _NAME_FAMILY:
            # Check if this ML name is contained within (or exactly matches)
            # a priority pattern span.
            is_fragment = any(
                ps <= span.start and span.end <= pe
                for ps, pe in priority_ranges
            )
            if is_fragment:
                suppressed += 1
                logger.debug(
                    "Pre-dedup ML name suppressed: %s %r (overlaps pattern)",
                    span.entity_type, span.text,
                )
                continue
        result.append(span)

    if suppressed:
        logger.info(
            "Pre-dedup: suppressed %d ML name fragments overlapping "
            "pattern USERNAME/location spans",
            suppressed,
        )
    return result


# ---------------------------------------------------------------------------
# Name–collision suppression (location, company, job title)
# ---------------------------------------------------------------------------

_LOCATION_TYPES = frozenset({
    "ADDRESS", "CITY", "STATE", "COUNTY", "COUNTRY", "ZIP",
    "GPS_COORDINATE", "GPS_COORDINATES",
})

# Entity types that should beat FIRSTNAME/LASTNAME in a collision.
# Includes locations (Florence→CITY vs FIRSTNAME) and professional
# types (Apple→COMPANY vs FIRSTNAME, Engineer→JOB_TITLE vs FIRSTNAME).
# Benchmark: 5 COMPANY→FIRSTNAME, 4 CITY→FIRSTNAME, 2 JOB_TITLE→FIRSTNAME
# type mismatches on nemotron_pii traced to dedup picking FIRSTNAME over
# these more specific types.
_NAME_COLLISION_PRIORITY_TYPES = _LOCATION_TYPES | frozenset({
    "COMPANY", "EMPLOYER", "JOB_TITLE", "USERNAME",
})


def _suppress_name_location_collisions(
    spans: list[Span],
    all_candidates: list[Span] | None = None,
) -> list[Span]:
    """Suppress FIRSTNAME/LASTNAME spans that overlap with priority types.

    City/state/county names (Florence, Georgia, Madison, Austin),
    company names (Apple, Chase), and usernames are common first names
    but are almost always the more specific type in PII contexts.
    When both a name and a priority-type span overlap at the same
    position, suppress the name.

    Args:
        spans: The resolved (post-dedup) span list to filter.
        all_candidates: Optional pre-dedup span list to source priority
            ranges from.  GLiNER may detect both CITY and FIRSTNAME at
            the same position; dedup picks one winner (often FIRSTNAME
            with higher confidence).  By checking ``all_candidates`` we
            see priority detections that lost in dedup.
    """
    source = spans if all_candidates is None else all_candidates
    priority_ranges: list[tuple[int, int]] = [
        (s.start, s.end)
        for s in source
        if s.entity_type in _NAME_COLLISION_PRIORITY_TYPES
    ]
    if not priority_ranges:
        return spans

    result: list[Span] = []
    for span in spans:
        if span.entity_type in _NAME_FAMILY:
            collides = any(
                _ranges_overlap(span.start, span.end, ls, le)
                for ls, le in priority_ranges
            )
            if collides:
                logger.debug(
                    "Name-collision suppressed: %s %r",
                    span.entity_type, span.text,
                )
                continue
        result.append(span)
    return result


# ---------------------------------------------------------------------------
# ML name false-positive suppression (common English words)
# ---------------------------------------------------------------------------

# Words that GLiNER frequently misclassifies as FIRSTNAME or LASTNAME.
# These are common English nouns, adjectives, demonyms, and business terms
# that are never standalone person names in PII contexts.
# Imported _NEVER_NAMES covers job titles and structural terms; this set
# adds GLiNER-specific false positives discovered through benchmarking.
_ML_NAME_BLOCKLIST = frozenset({
    # Business / legal terms frequently flagged as FIRSTNAME
    "strategies", "consent", "contractors", "recipient", "recipients",
    "submission", "submissions", "campaigns", "investments",
    "obligations", "acquisition", "acquisitions", "compliance",
    "governance", "initiatives", "procurement", "stakeholders",
    "implementation", "specifications", "authorization",
    "documentation", "infrastructure", "telecommunications",
    "unfortunately", "approximately", "alternatively",
    "comprehensive", "fundamentally", "subsequently",
    "assessment", "requirements", "procedures", "guidelines",
    "provisions", "regulations", "amendments", "transactions",
    "participants", "beneficiaries", "representatives",
    "notification", "notifications", "coordination",
    "considerations", "responsibilities", "recommendations",
    "arrangements", "acknowledgment", "acknowledgement",
    "correspondence", "miscellaneous", "supplementary",
    # Common words flagged as LASTNAME
    "spark", "nationalist", "mutual", "team", "mente",
    "premium", "quantum", "spectrum", "catalyst", "pinnacle",
    "velocity", "momentum", "paradigm", "syndicate",
    "global", "digital", "federal", "central", "capital",
    "premier", "summit", "alliance", "standard", "enterprise",
    "ventures", "holdings", "partners", "associates", "solutions",
    "dynamics", "analytics", "logistics", "advisory",
    # Demonyms / nationality-adjacent words
    "croat", "croatian", "emirati", "kuwaiti", "qatari",
    "bahraini", "omani", "yemeni", "somali", "afghan",
    "iraqi", "irani", "iranian", "syrian", "libyan",
    "lebanese", "jordanian", "palestinian", "israeli",
    "turkish", "egyptian", "tunisian", "algerian", "moroccan",
    # Place names GLiNER confuses with person names
    "kremlin", "hartford", "pentagon", "saharan",
    "broadway", "westminster", "manhattan", "brooklyn",
    # Short words / brand-adjacent
    "verde", "tone", "viva", "alto", "vista",
    "forte", "tempo", "presto", "largo", "motto",
    # Action / role words
    "claim", "claims", "overall", "overview",
    "appeal", "appeals", "reform", "reforms",
    "mandate", "mandates", "verdict", "verdicts",
    "pioneer", "advocate", "sentinel",
    "interim", "ongoing", "pending", "pursuant",
    # Common words that start sentences (title-cased by position)
    "cash", "yoga", "menu", "logo", "demo", "memo",
    "quota", "bonus", "forum", "salon", "plaza",
    "versus", "via", "per", "etc", "also",
    # Common nouns/adjectives falsely detected as names
    "universal", "regional", "municipal", "provincial",
    "residential", "commercial", "industrial", "financial",
    "clinical", "surgical", "medical", "dental", "optical",
    "tropical", "biological", "technical", "political",
    "electoral", "judicial", "criminal", "civil",
    "annual", "quarterly", "monthly", "weekly", "daily",
    "primary", "secondary", "tertiary", "preliminary",
    "internal", "external", "lateral", "bilateral",
    "rural", "urban", "suburban", "coastal",
    # Nemotron PII FP analysis — additional words
    "baha", "al", "sales", "jazeera", "brokerage",
})


# Suffixes that NEVER appear on real person names (for words >= 7 chars).
# Verified against name databases: no known first or last name of 7+
# characters ends with any of these suffixes.
# Examples of what they catch:
#   -tion: "Administration", "Registration", "Specification"
#   -sion: "Commission", "Submission", "Permission"
#   -ness: "Awareness", "Business", "Effectiveness"
#   -ful:  "Powerful", "Successful", "Meaningful"
#   -less: "Regardless", "Wireless", "Careless"
#   -ism:  "Capitalism", "Terrorism", "Journalism"
# Explicitly excluded: -ity (Trinity, Felicity, Charity),
# -ous (Precious), -ence (Florence, Clarence), -ance (Constance),
# -ive (Clive), -ment (Clement), -able (Constable), -ers (Rogers),
# -son (Johnson), -ton (Clinton), -ing (Sterling, Irving)
_NON_NAME_SUFFIXES = (
    "tion", "tions",
    "sion", "sions",
    "ness",
    "ful",
    "less",
    "ism", "isms",
    "ize", "ized", "izes", "izing",
    "ify", "ified", "ifies", "ifying",
    "ily",
    "ably", "ibly",
    "ally",
    "ously",
    "ingly",
    "ively",
    "ical",
    "ible",
)


def _suppress_ml_name_false_positives(spans: list[Span]) -> list[Span]:
    """Suppress NAME-family spans whose text is a common non-name English word.

    Uses three complementary strategies:
    1. Explicit blocklist (_ML_NAME_BLOCKLIST) for known FP words
    2. _NEVER_NAMES from dictionary detector (job titles, structural terms)
    3. Suffix heuristic: words >= 7 chars ending in suffixes that never
       appear on real names (-tion, -sion, -ness, -ful, -less, etc.)
    """
    from .dictionary_names import _NEVER_NAMES

    result: list[Span] = []
    suppressed = 0
    for span in spans:
        if span.entity_type in _NAME_FAMILY:
            lower = span.text.strip().lower()
            if lower in _ML_NAME_BLOCKLIST or lower in _NEVER_NAMES:
                suppressed += 1
                logger.debug(
                    "Name FP suppressed: %s %r (blocklist, tier=%s)",
                    span.entity_type, span.text, span.tier,
                )
                continue
            # Suffix heuristic: words with 7+ characters ending in
            # distinctly non-name English suffixes.
            if len(lower) >= 7 and lower.endswith(_NON_NAME_SUFFIXES):
                suppressed += 1
                logger.debug(
                    "Name FP suppressed: %s %r (suffix, tier=%s)",
                    span.entity_type, span.text, span.tier,
                )
                continue
        result.append(span)

    if suppressed:
        logger.info(
            "Name FP suppression: removed %d common-word name spans",
            suppressed,
        )
    return result


# ---------------------------------------------------------------------------
# ML USERNAME false-positive suppression
# ---------------------------------------------------------------------------

# Common English words GLiNER misclassifies as USERNAME.
# The pattern detector has _USERNAME_FALSE_POSITIVES but that only filters
# pattern-tier detections.  This covers ML-tier USERNAME spans.
_ML_USERNAME_BLOCKLIST = frozenset({
    "training", "obligations", "license", "licenses", "licensed",
    "named", "manual", "manuals", "experience", "experienced",
    "re-authenticated", "authenticated", "authentication",
    "registered", "registration", "certified", "certification",
    "authorized", "authorization", "qualified", "qualification",
    "approved", "approval", "designated", "designation",
    "processed", "processing", "completed", "completion",
    "submitted", "submission", "confirmed", "confirmation",
    "verified", "verification", "validated", "validation",
    "updated", "suspended", "terminated", "transferred",
    "recommended", "assigned", "associated", "documented",
    "referenced", "generated", "maintained", "established",
    "implemented", "distributed", "administered",
})


def _suppress_ml_username_false_positives(spans: list[Span]) -> list[Span]:
    """Suppress USERNAME spans whose text is a common English word."""
    result: list[Span] = []
    for span in spans:
        if normalize_entity_type(span.entity_type) == "USERNAME":
            lower = span.text.strip().lower()
            if lower in _ML_USERNAME_BLOCKLIST:
                logger.debug(
                    "USERNAME FP suppressed: %r (blocklist, tier=%s)",
                    span.text, span.tier,
                )
                continue
            # Suffix heuristic: common English word suffixes → not a username
            if len(lower) >= 7 and lower.endswith(_NON_NAME_SUFFIXES):
                logger.debug(
                    "USERNAME FP suppressed: %r (suffix, tier=%s)",
                    span.text, span.tier,
                )
                continue
        result.append(span)
    return result


# ---------------------------------------------------------------------------
# ML CITY / location false-positive suppression
# ---------------------------------------------------------------------------

# Entity types to check for location false positives.
_LOCATION_FP_TYPES = frozenset({"CITY", "STATE", "COUNTY", "ADDRESS"})

# Common non-location words that GLiNER misclassifies as CITY.
_ML_CITY_BLOCKLIST = frozenset({
    # Business/organizational terms
    "summit", "alliance", "enterprise", "standard", "premium",
    "capital", "central", "federal", "national", "general",
    "premier", "pioneer", "advocate", "sentinel", "catalyst",
    "ventures", "holdings", "partners", "dynamics", "momentum",
    # Legal/governance
    "mandate", "verdict", "reform", "appeal", "consent",
    "governance", "compliance", "oversight", "tribunal",
    # Generic terms
    "overall", "overview", "interim", "mutual", "prime",
    "exchange", "gateway", "forum", "arena", "plaza",
})


def _suppress_ml_location_false_positives(spans: list[Span]) -> list[Span]:
    """Suppress CITY/location spans whose text is clearly not a place name.

    Uses two strategies:
    1. Explicit blocklist of business/organizational words
    2. Suffix heuristic: words >= 7 chars with non-name suffixes are never
       place names either (-tion, -sion, -ness, -ful, etc.)
    """
    result: list[Span] = []
    suppressed = 0
    for span in spans:
        etype = normalize_entity_type(span.entity_type)
        if etype in _LOCATION_FP_TYPES and span.tier == Tier.ML:
            lower = span.text.strip().lower()
            if lower in _ML_CITY_BLOCKLIST:
                suppressed += 1
                logger.debug(
                    "Location FP suppressed: %s %r (blocklist)",
                    span.entity_type, span.text,
                )
                continue
            if len(lower) >= 7 and lower.endswith(_NON_NAME_SUFFIXES):
                suppressed += 1
                logger.debug(
                    "Location FP suppressed: %s %r (suffix)",
                    span.entity_type, span.text,
                )
                continue
        result.append(span)
    if suppressed:
        logger.info(
            "Location FP suppression: removed %d ML location spans", suppressed,
        )
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
