"""Detector orchestrator - runs all detectors in parallel.

Detectors are organized by domain:
- checksum.py: Checksum-validated identifiers (SSN, CC, NPI, DEA, VIN, IBAN, ABA)
- patterns.py: PII/PHI patterns (names, dates, addresses, phones, medical IDs)
- additional_patterns.py: EMPLOYER, AGE, HEALTH_PLAN_ID patterns
- secrets.py: API keys, tokens, credentials, private keys
- financial.py: Security identifiers (CUSIP, ISIN, SWIFT) and crypto
- government.py: Classification markings, CAGE codes, contracts
- regulated_sectors.py: FERPA (education), Legal, Immigration identifiers
- dictionaries.py: Dictionary-based detection

Concurrency Model:
    Uses ThreadPoolExecutor for parallel pattern matching across domains.
    Pattern matching is I/O-bound (regex on text) so GIL isn't a bottleneck.

Resource Management:
    All thread pool and backpressure state is managed via Context instances.
    If no Context is provided, a default context is created automatically.
    This ensures proper resource isolation and cleanup.

For thread timeout limitations and mitigations, see thread_pool.py.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError, Future
from contextlib import contextmanager
from typing import List, Optional, Dict, Tuple, TYPE_CHECKING

from ..types import Span, Tier, CLINICAL_CONTEXT_TYPES
from ..config import Config
from ..constants import DETECTOR_TIMEOUT

if TYPE_CHECKING:
    from ....context import Context

# Import from split modules
from .metadata import (
    DetectionMetadata,
    DetectionQueueFullError,
    DetectorFailureError,
)

# Detector imports
from .base import BaseDetector
from .checksum import ChecksumDetector
from .patterns import PatternDetector  # patterns/ module
from .additional_patterns import AdditionalPatternDetector
from .dictionaries import DictionaryDetector
from .structured import extract_structured_phi, post_process_ocr, map_span_to_original

# Domain-specific detectors
from .secrets import SecretsDetector
from .financial import FinancialDetector
from .government import GovernmentDetector
from .regulated_sectors import RegulatedSectorDetector

# Pipeline imports
from ..pipeline.merger import filter_tracking_numbers
from ..pipeline.confidence import normalize_spans_confidence

# Confidence constant for known entities
from .constants import CONFIDENCE_VERY_HIGH

# Context enhancement - optional
ContextEnhancer = None
create_enhancer = None
try:
    from .context_enhancer import ContextEnhancer, create_enhancer
except ImportError:
    pass


logger = logging.getLogger(__name__)


class DetectorOrchestrator:
    """
    Runs all detectors and combines results.

    Pipeline:
    1. Structured extractor (OCR post-processing + label-based extraction)
    2. All other detectors in parallel on processed text
    3. Combine results with structured spans getting higher tier
    4. Context enhancement (optional) - filters obvious false positives

    Detector Categories:
    - Core PII/PHI: ChecksumDetector, PatternDetector, AdditionalPatternDetector, DictionaryDetector
    - Secrets: SecretsDetector (API keys, tokens, credentials)
    - Financial: FinancialDetector (CUSIP, ISIN, crypto)
    - Government: GovernmentDetector (classification, contracts)

    Features:
    - Parallel execution via shared ThreadPoolExecutor
    - Timeout per detector (graceful degradation)
    - Failures don't affect other detectors
    - Selective detector enablement via config

    Supports optional Context parameter for resource isolation.
    All thread pool and backpressure state is managed via Context.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        parallel: bool = True,
        enable_structured: bool = True,
        enable_secrets: bool = True,
        enable_financial: bool = True,
        enable_government: bool = True,
        context: Optional["Context"] = None,
    ):
        """
        Initialize the detector orchestrator.

        Args:
            config: Configuration object
            parallel: Run detectors in parallel (recommended)
            enable_structured: Enable OCR post-processing and label extraction
            enable_secrets: Enable secrets detection (API keys, tokens)
            enable_financial: Enable financial identifier detection (CUSIP, crypto)
            enable_government: Enable government/classification detection
            context: Optional Context for resource isolation.
                    If not provided, a default context is created automatically.
                    All thread pool and backpressure state is managed via the context.
        """
        self.config = config or Config()
        self.parallel = parallel
        self.enable_structured = enable_structured

        # Create context if not provided - ensures proper resource management
        if context is None:
            from ....context import get_default_context
            context = get_default_context(warn=False)
        self._context = context

        # Get disabled detectors from config
        disabled = self.config.disabled_detectors if self.config else set()

        # Initialize core detectors (unless disabled)
        self._detectors: List[BaseDetector] = []

        if "checksum" not in disabled:
            self._detectors.append(ChecksumDetector())
        if "patterns" not in disabled:
            self._detectors.append(PatternDetector())
        if "additional_patterns" not in disabled:
            self._detectors.append(AdditionalPatternDetector())

        # Add domain-specific detectors based on configuration
        if enable_secrets and "secrets" not in disabled:
            self._detectors.append(SecretsDetector())
            logger.info("SecretsDetector enabled (API keys, tokens, credentials)")

        if enable_financial and "financial" not in disabled:
            self._detectors.append(FinancialDetector())
            logger.info("FinancialDetector enabled (CUSIP, ISIN, crypto)")

        if enable_government and "government" not in disabled:
            self._detectors.append(GovernmentDetector())
            logger.info("GovernmentDetector enabled (classification, contracts)")

        # Regulated sectors (FERPA, Legal, Immigration) - always enabled unless disabled
        if "regulated_sectors" not in disabled:
            self._detectors.append(RegulatedSectorDetector())
            logger.info("RegulatedSectorDetector enabled (FERPA, legal, immigration)")

        # Add dictionary detector if dictionaries exist
        if "dictionaries" not in disabled and self.config.dictionaries_dir.exists():
            self._detectors.append(DictionaryDetector(self.config.dictionaries_dir))
            logger.info(f"DictionaryDetector enabled ({self.config.dictionaries_dir})")

        # Cache available detectors (checked once at init, not on every detect call)
        # Detector availability doesn't change after loading
        self._available_detectors: List[BaseDetector] = [
            d for d in self._detectors if d.is_available()
        ]

        # Log detector summary
        detector_names = [d.name for d in self._detectors]
        available_names = [d.name for d in self._available_detectors]
        logger.info(
            f"DetectorOrchestrator initialized with {len(self._detectors)} detectors "
            f"({len(self._available_detectors)} available)"
        )
        logger.info(f"  All detectors: {detector_names}")
        logger.info(f"  Available detectors: {available_names}")
        unavailable = set(detector_names) - set(available_names)
        if unavailable:
            logger.warning(f"  Unavailable detectors: {unavailable}")

        # Context enhancer (optional) - filters obvious false positives
        self._context_enhancer = None
        if create_enhancer is not None:
            try:
                self._context_enhancer = create_enhancer()
                logger.info("Context Enhancer: Enabled")
            except Exception as e:
                logger.debug(f"Context Enhancer not available: {e}")

        # LLM verifier not included - detection only, no LLM calls
        self._llm_verifier = None

    @property
    def active_detector_names(self) -> List[str]:
        """Get names of available detectors."""
        return [d.name for d in self._available_detectors]

    def _get_executor(self) -> ThreadPoolExecutor:
        """Get the thread pool executor from context."""
        return self._context.get_executor()

    @contextmanager
    def _get_detection_slot(self):
        """
        Get a detection slot with backpressure control.

        Yields:
            Current queue depth
        """
        with self._context.detection_slot() as depth:
            yield depth

    def _track_runaway(self, detector_name: str) -> int:
        """
        Track a runaway detection thread.

        Returns:
            Current runaway detection count
        """
        return self._context.track_runaway_detection(detector_name)

    MAX_MATCHES_PER_TERM = 100  # HIGH-009: prevent memory exhaustion

    def _detect_known_entities(
        self,
        text: str,
        known_entities: Dict[str, tuple],
    ) -> List[Span]:
        """
        Detect occurrences of known entities in text.

        This provides entity persistence across messages - if "John" was identified
        as a name in message 1, it will be detected with high confidence in message 2
        even without contextual cues.

        Args:
            text: The text to search
            known_entities: Dict from TokenStore: {token: (value, entity_type)}

        Returns:
            List of high-confidence spans for known entity matches
        """
        spans = []
        text_lower = text.lower()

        for token, (value, entity_type) in known_entities.items():
            value_lower = value.lower()

            # Search for full value and individual name parts (partial matching)
            # e.g., if we know "John Smith", also detect standalone "John" or "Smith"
            search_terms = [value_lower]
            if ' ' in value_lower:
                parts = value_lower.split()
                # Only add parts that are 2+ characters (avoid matching "J.")
                search_terms.extend(p for p in parts if len(p) >= 2)

            for search_term in search_terms:
                start = 0
                match_count = 0
                while True:
                    idx = text_lower.find(search_term, start)
                    if idx == -1:
                        break

                    if match_count >= self.MAX_MATCHES_PER_TERM:  # HIGH-009
                        logger.debug(f"Reached max matches ({self.MAX_MATCHES_PER_TERM}) for known entity")
                        break

                    end = idx + len(search_term)

                    # Check word boundaries to avoid matching "Johnson" when searching "John"
                    valid_start = idx == 0 or not text[idx - 1].isalnum()
                    valid_end = end >= len(text) or not text[end].isalnum()

                    if valid_start and valid_end:
                        # Get original case from text
                        original_text = text[idx:end]

                        # Only match if it looks like a proper noun (capitalized)
                        if original_text and original_text[0].isupper():
                            span = Span(
                                start=idx,
                                end=end,
                                text=original_text,
                                entity_type=entity_type,
                                confidence=CONFIDENCE_VERY_HIGH,  # Very high - we KNOW this is an entity
                                detector="known_entity",
                                tier=Tier.STRUCTURED,  # High tier to bypass context enhancement
                            )
                            spans.append(span)
                            match_count += 1
                            # Don't log actual PII values - log position and type only
                            logger.debug(
                                f"Known entity match: {entity_type} at pos {start}-{end} (len={len(original_text)})"
                            )

                    start = end

        return spans

    def detect(
        self,
        text: str,
        timeout: float = DETECTOR_TIMEOUT,
        known_entities: Optional[Dict[str, tuple]] = None,
    ) -> List[Span]:
        """
        Run all detectors on text.

        Args:
            text: Normalized input text
            timeout: Max seconds per detector
            known_entities: Optional dict of known entities from TokenStore.
                           Format: {token: (value, entity_type)}
                           These are detected with high confidence (0.98) for
                           entity persistence across messages.

        Returns:
            Combined spans from all detectors (may overlap), in original text coordinates

        Raises:
            DetectionQueueFullError: If queue depth exceeds MAX_QUEUE_DEPTH
        """
        if not text:
            return []

        # Context-aware detection slot
        with self._get_detection_slot() as queue_depth:
            logger.info(f"Detection starting on text ({len(text)} chars), queue depth: {queue_depth}")
            return self._detect_impl(text, timeout, known_entities)

    def detect_with_metadata(
        self,
        text: str,
        timeout: float = DETECTOR_TIMEOUT,
        known_entities: Optional[Dict[str, tuple]] = None,
        strict_mode: bool = False,
    ) -> Tuple[List[Span], DetectionMetadata]:
        """
        Run all detectors on text and return metadata about the detection process.

        This method provides visibility into detector failures and degraded state.

        Args:
            text: Normalized input text
            timeout: Max seconds per detector
            known_entities: Optional dict of known entities from TokenStore
            strict_mode: If True, raise DetectorFailureError when any detector
                        fails (LOW-004). Use for compliance scanning where
                        complete coverage is required. Default: False (tolerant).

        Returns:
            Tuple of (spans, metadata) where metadata contains:
            - detectors_run: List of detectors that succeeded
            - detectors_failed: List of detectors that failed
            - warnings: Warning messages
            - degraded: True if structured extractor failed
            - all_detectors_failed: True if no detectors succeeded

        Raises:
            DetectionQueueFullError: If queue depth exceeds MAX_QUEUE_DEPTH
            DetectorFailureError: If strict_mode=True and any detector fails (LOW-004)
        """
        if not text:
            return [], DetectionMetadata()

        # Context-aware detection slot
        with self._get_detection_slot() as queue_depth:
            logger.info(f"Detection starting on text ({len(text)} chars), queue depth: {queue_depth}")
            metadata = DetectionMetadata()
            spans = self._detect_impl_with_metadata(text, timeout, known_entities, metadata)
            metadata.finalize()

            if strict_mode and (metadata.detectors_failed or metadata.detectors_timed_out):  # LOW-004
                all_failed = metadata.detectors_failed + metadata.detectors_timed_out
                raise DetectorFailureError(all_failed, metadata)

            return spans, metadata

    def _detect_impl(
        self,
        text: str,
        timeout: float,
        known_entities: Optional[Dict[str, tuple]],
    ) -> List[Span]:
        """Internal detection implementation (called with semaphore held)."""
        # Delegate to the metadata-tracking version but discard metadata
        metadata = DetectionMetadata()
        return self._detect_impl_with_metadata(text, timeout, known_entities, metadata)

    def _detect_impl_with_metadata(
        self,
        text: str,
        timeout: float,
        known_entities: Optional[Dict[str, tuple]],
        metadata: DetectionMetadata,
    ) -> List[Span]:
        """
        Internal detection implementation with metadata tracking.

        This is the core detection logic that tracks all failures and degraded state.
        Orchestrates the detection pipeline:
        1. Known entity detection (entity persistence)
        2. Structured extraction (OCR post-processing)
        3. Pattern/ML detectors (parallel or sequential)
        4. Coordinate mapping (processed -> original text)
        5. Post-processing (filter, dedupe, normalize, enhance)
        """
        all_spans: List[Span] = []

        # Step 0: Known entity detection (entity persistence across messages)
        if known_entities:
            known_spans = self._run_known_entity_detection(text, known_entities)
            all_spans.extend(known_spans)

        # Step 1: Structured extraction (OCR + label-based)
        processed_text, char_map, structured_spans = self._run_structured_extraction(
            text, metadata
        )
        all_spans.extend(structured_spans)

        # Step 2: Run pattern/ML detectors
        detector_spans = self._run_detectors(processed_text, timeout, metadata)
        if detector_spans is None:
            # No detectors available - return what we have
            return all_spans

        # Step 3: Map detector spans back to original text coordinates
        mapped_spans = self._map_spans_to_original(
            detector_spans, char_map, processed_text, text
        )
        all_spans.extend(mapped_spans)

        # Step 4: Post-processing pipeline
        return self._postprocess_spans(all_spans, text)

    def _run_known_entity_detection(
        self,
        text: str,
        known_entities: Dict[str, tuple],
    ) -> List[Span]:
        """
        Step 0: Detect previously-identified entities.

        Provides entity persistence across messages - if "John" was identified
        as a name in message 1, it will be detected with high confidence in
        message 2 even without contextual cues.
        """
        spans = self._detect_known_entities(text, known_entities)
        if spans:
            logger.info(f"Known entity detection: {len(spans)} matches from entity memory")
        return spans

    def _run_structured_extraction(
        self,
        text: str,
        metadata: DetectionMetadata,
    ) -> Tuple[str, List[int], List[Span]]:
        """
        Step 1: Run structured extractor with OCR post-processing.

        Returns:
            Tuple of (processed_text, char_map, structured_spans)
            - processed_text: OCR-corrected text for pattern matching
            - char_map: Position mapping from processed to original
            - structured_spans: Spans from label-based extraction
        """
        if not self.enable_structured:
            return text, [], []

        try:
            processed_text, char_map = post_process_ocr(text)
            structured_result = extract_structured_phi(text)

            if structured_result.spans:
                logger.debug(
                    f"Structured extractor: {structured_result.fields_extracted} fields, "
                    f"{len(structured_result.spans)} spans"
                )

            return processed_text, char_map, structured_result.spans

        except (ValueError, RuntimeError) as e:
            logger.error(f"Structured extractor failed: {e}")
            metadata.structured_extractor_failed = True
            metadata.degraded = True
            metadata.warnings.append(f"Structured extraction failed: {type(e).__name__}: {e}")
            return text, [], []

    def _run_detectors(
        self,
        text: str,
        timeout: float,
        metadata: DetectionMetadata,
    ) -> Optional[List[Span]]:
        """
        Step 2: Run pattern/ML detectors on text.

        Returns:
            List of spans, or None if no detectors available
        """
        available = self._available_detectors

        if not available:
            logger.warning("No traditional detectors available, using only structured extraction")
            metadata.warnings.append("No traditional detectors available")
            return None

        if self.parallel and len(available) > 1:
            return self._detect_parallel(text, available, timeout, metadata)
        else:
            return self._detect_sequential(text, available, timeout, metadata)

    def _map_spans_to_original(
        self,
        spans: List[Span],
        char_map: List[int],
        processed_text: str,
        original_text: str,
    ) -> List[Span]:
        """
        Step 3: Map span coordinates from processed text back to original.

        When OCR post-processing modifies text (fixing common OCR errors),
        span positions need to be mapped back to the original text.
        """
        if not char_map or processed_text == original_text:
            return spans

        mapped_spans = []
        for span in spans:
            orig_start, orig_end = map_span_to_original(
                span.start, span.end, span.text, char_map, original_text
            )
            orig_text = (
                original_text[orig_start:orig_end]
                if orig_start < len(original_text)
                else span.text
            )

            mapped_spans.append(Span(
                start=orig_start,
                end=orig_end,
                text=orig_text,
                entity_type=span.entity_type,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
            ))

        return mapped_spans

    def _postprocess_spans(
        self,
        spans: List[Span],
        text: str,
    ) -> List[Span]:
        """
        Step 4: Post-processing pipeline.

        Applies filters, deduplication, normalization, and enhancement:
        1. Filter clinical context types (non-PHI)
        2. Deduplicate overlapping spans
        3. Filter tracking number false positives
        4. Normalize confidence scores
        5. Context enhancement (rule-based FP filtering)
        6. LLM verification (optional, for ambiguous cases)
        """
        # 1. Filter clinical context types BEFORE deduplication
        pre_clinical_count = len(spans)
        spans = [s for s in spans if s.entity_type.upper() not in CLINICAL_CONTEXT_TYPES]
        clinical_filtered = pre_clinical_count - len(spans)
        if clinical_filtered > 0:
            logger.info(
                f"Clinical context filter: Removed {clinical_filtered} "
                "non-PHI entities (LAB_TEST, DIAGNOSIS, etc.)"
            )

        # 2. Deduplicate spans (same position + text = duplicate)
        spans = self._dedupe_spans(spans)

        # 3. Filter ML false positives: carrier names/tracking numbers
        spans = filter_tracking_numbers(spans, text)

        # 4. Normalize confidence scores across detectors
        spans = normalize_spans_confidence(spans)

        # 5. Context enhancement (fast, rule-based filtering)
        spans = self._apply_context_enhancement(spans, text)

        # 6. LLM verification (optional)
        spans = self._apply_llm_verification(spans, text)

        # Log final results (SECURITY: never log actual PHI text)
        self._log_detection_results(spans)

        return spans

    def _apply_context_enhancement(
        self,
        spans: List[Span],
        text: str,
    ) -> List[Span]:
        """Apply context enhancement to filter obvious false positives."""
        if self._context_enhancer is None or not spans:
            return spans

        pre_count = len(spans)
        spans = self._context_enhancer.enhance(text, spans)
        filtered = pre_count - len(spans)

        if filtered > 0:
            logger.info(f"Context Enhancer: Filtered {filtered} obvious FPs")

        return spans

    def _apply_llm_verification(
        self,
        spans: List[Span],
        text: str,
    ) -> List[Span]:
        """Apply LLM verification to ambiguous spans."""
        if self._llm_verifier is None or not spans:
            return spans

        # Only send ambiguous spans to LLM (those with needs_review=True)
        needs_llm = [s for s in spans if getattr(s, 'needs_review', False)]
        already_verified = [s for s in spans if not getattr(s, 'needs_review', False)]

        if not needs_llm:
            logger.debug("LLM Verifier: No spans need verification")
            return spans

        pre_count = len(needs_llm)
        verified = self._llm_verifier.verify(text, needs_llm)
        filtered = pre_count - len(verified)

        if filtered > 0:
            logger.info(f"LLM Verifier: Filtered {filtered} false positives")

        return already_verified + verified

    def _log_detection_results(self, spans: List[Span]) -> None:
        """Log final detection results (metadata only, no PHI)."""
        if spans:
            final_summary = [
                (s.entity_type, s.detector, f"{s.confidence:.2f}")
                for s in spans
            ]
            logger.info(
                f"Detection complete: {len(spans)} final spans after dedup: {final_summary}"
            )
        else:
            logger.info("Detection complete: 0 spans detected")

    def detect_with_processed_text(self, text: str, timeout: float = DETECTOR_TIMEOUT) -> Tuple[List[Span], str]:
        """
        Run all detectors and return both spans and processed text.

        Useful when caller needs the OCR-corrected text.

        Returns:
            Tuple of (spans, processed_text)
        """
        if not text:
            return [], text

        all_spans: List[Span] = []
        processed_text = text

        # Step 1: Run structured extractor first
        if self.enable_structured:
            try:
                structured_result = extract_structured_phi(text)
                all_spans.extend(structured_result.spans)
                processed_text = structured_result.processed_text
            except (ValueError, RuntimeError) as e:
                logger.error(f"Structured extractor failed: {e}")

        # Step 2: Run all other detectors (use cached availability for performance)
        available = self._available_detectors

        if available:
            if self.parallel and len(available) > 1:
                other_spans = self._detect_parallel(processed_text, available, timeout)
            else:
                other_spans = self._detect_sequential(processed_text, available)
            all_spans.extend(other_spans)

        deduped = self._dedupe_spans(all_spans)
        # Normalize confidence scores
        normalized = normalize_spans_confidence(deduped)
        return normalized, processed_text

    def _dedupe_spans(self, spans: List[Span]) -> List[Span]:
        """
        Remove duplicate spans at the same position.

        Strategy:
        1. First, group by (start, end, entity_type) and keep best per type
        2. Then, group by (start, end) and keep highest tier/confidence overall

        This ensures only ONE span per position in the output.
        """
        if not spans:
            return spans

        # Step 1: Group by (start, end, entity_type) - keep best per type
        type_seen: Dict[Tuple[int, int, str], Span] = {}

        for span in spans:
            key = (span.start, span.end, span.entity_type)

            if key not in type_seen:
                type_seen[key] = span
            else:
                existing = type_seen[key]
                # Prefer higher tier, then higher confidence
                if (span.tier.value > existing.tier.value or
                    (span.tier.value == existing.tier.value and
                     span.confidence > existing.confidence)):
                    type_seen[key] = span

        # Step 2: Group by (start, end) only - keep highest tier/confidence overall
        # This resolves conflicting entity types at the same position
        position_seen: Dict[Tuple[int, int], Span] = {}

        for span in type_seen.values():
            key = (span.start, span.end)

            if key not in position_seen:
                position_seen[key] = span
            else:
                existing = position_seen[key]
                # Prefer higher tier, then higher confidence
                if (span.tier.value > existing.tier.value or
                    (span.tier.value == existing.tier.value and
                     span.confidence > existing.confidence)):
                    position_seen[key] = span

        return list(position_seen.values())

    def _detect_sequential(
        self,
        text: str,
        detectors: List[BaseDetector],
        timeout: float = DETECTOR_TIMEOUT,
        metadata: Optional[DetectionMetadata] = None,
    ) -> List[Span]:
        """
        Run detectors sequentially with per-detector timeout.

        Args:
            text: Text to analyze
            detectors: List of detectors to run
            timeout: Total timeout budget
            metadata: Optional metadata object to track failures
        """
        all_spans = []
        executor = self._get_executor()

        # Per-detector timeout (divide total timeout among detectors)
        per_detector_timeout = timeout / max(len(detectors), 1)

        for detector in detectors:
            try:
                # Use executor for timeout protection even in sequential mode
                future = executor.submit(detector.detect, text)
                spans = future.result(timeout=per_detector_timeout)
                all_spans.extend(spans)

                if metadata:
                    metadata.add_success(detector.name)

                if spans:
                    # SECURITY: Log only metadata, not actual PHI values
                    span_summary = [(s.entity_type, f"{s.confidence:.2f}") for s in spans]
                    logger.info(f"  {detector.name}: {len(spans)} spans: {span_summary}")
                else:
                    logger.info(f"  {detector.name}: 0 spans")

            except TimeoutError:
                cancelled = future.cancel()
                if metadata:
                    metadata.add_timeout(detector.name, per_detector_timeout, cancelled)
                    if not cancelled:
                        metadata.runaway_threads = self._track_runaway(detector.name)
                logger.warning(
                    f"Detector {detector.name} timed out after {per_detector_timeout:.1f}s "
                    f"(sequential mode, cancelled={cancelled})"
                )

            except Exception as e:
                if metadata:
                    metadata.add_failure(detector.name, str(e))
                logger.error(f"Detector {detector.name} failed: {e}")

        return all_spans

    def _detect_parallel(
        self,
        text: str,
        detectors: List[BaseDetector],
        timeout: float = DETECTOR_TIMEOUT,
        metadata: Optional[DetectionMetadata] = None,
    ) -> List[Span]:
        """
        Run detectors in parallel with timeout.

        Args:
            text: Text to analyze
            detectors: List of detectors to run
            timeout: Timeout per detector
            metadata: Optional metadata object to track failures
        """
        all_spans = []
        executor = self._get_executor()

        logger.info(f"Running {len(detectors)} detectors in parallel...")

        # Submit all tasks
        futures: Dict[Future, BaseDetector] = {
            executor.submit(d.detect, text): d
            for d in detectors
        }

        # Collect results with timeout
        for future in futures:
            detector = futures[future]
            try:
                spans = future.result(timeout=timeout)
                all_spans.extend(spans)

                if metadata:
                    metadata.add_success(detector.name)

                if spans:
                    # SECURITY: Log only metadata, not actual PHI values
                    span_summary = [(s.entity_type, f"{s.confidence:.2f}") for s in spans]
                    logger.info(f"  {detector.name}: {len(spans)} spans: {span_summary}")
                else:
                    logger.info(f"  {detector.name}: 0 spans")

            except TimeoutError:
                # Best effort cancel - Python threads can't be forcibly killed
                cancelled = future.cancel()
                if metadata:
                    metadata.add_timeout(detector.name, timeout, cancelled)
                    if not cancelled:
                        metadata.runaway_threads = self._track_runaway(detector.name)

                logger.warning(
                    f"Detector {detector.name} timed out after {timeout}s "
                    f"(cancelled={cancelled})"
                )

            except Exception as e:
                if metadata:
                    metadata.add_failure(detector.name, str(e))
                logger.error(f"Detector {detector.name} failed: {e}")

        return all_spans

    def get_detector_info(self) -> List[Dict]:
        """Get information about loaded detectors."""
        return [
            {
                "name": d.name,
                "tier": d.tier.name,
                "available": d.is_available(),
            }
            for d in self._detectors
        ]


def detect_all(
    text: str,
    config: Optional[Config] = None,
    enable_secrets: bool = True,
    enable_financial: bool = True,
    enable_government: bool = True,
) -> List[Span]:
    """
    Convenience function to detect all PHI/PII.

    Creates orchestrator, runs detection, returns spans.

    Args:
        text: Text to analyze
        config: Optional configuration
        enable_secrets: Enable API key/token detection
        enable_financial: Enable financial identifier detection
        enable_government: Enable classification/government detection

    Returns:
        List of detected spans
    """
    orchestrator = DetectorOrchestrator(
        config=config,
        enable_secrets=enable_secrets,
        enable_financial=enable_financial,
        enable_government=enable_government,
    )
    return orchestrator.detect(text)


# Re-export for backward compatibility
__all__ = [
    # Main class
    'DetectorOrchestrator',
    # Convenience function
    'detect_all',
    # Metadata and exceptions (from metadata.py)
    'DetectionMetadata',
    'DetectionQueueFullError',
    'DetectorFailureError',
]
