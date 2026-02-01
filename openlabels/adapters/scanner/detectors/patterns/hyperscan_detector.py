"""
Hyperscan-accelerated pattern detector for high-performance scanning.

Uses Intel Hyperscan library for SIMD-accelerated regex matching.
Compatible patterns (97%) are compiled into a single database and scanned in one pass,
providing 10-50x speedup over sequential pattern matching.

Patterns with lookahead/lookbehind assertions (unsupported by Hyperscan) are
run separately using the standard regex module.

Falls back to standard PatternDetector if Hyperscan is unavailable.
"""

import logging
import re as stdlib_re
from typing import List, Dict, Tuple, Optional, Any, Set
from dataclasses import dataclass

from ...types import Span, Tier
from ..base import BaseDetector
from .definitions import PATTERNS
from .false_positives import is_false_positive_name
from .validators import (
    validate_ip,
    validate_phone,
    validate_date,
    validate_age,
    validate_luhn,
    validate_vin,
    validate_ssn_context,
)

logger = logging.getLogger(__name__)

# Try to import hyperscan
try:
    import hyperscan
    _HYPERSCAN_AVAILABLE = True
except ImportError:
    _HYPERSCAN_AVAILABLE = False
    logger.info("Hyperscan not available, using standard pattern detector")


def _is_hyperscan_compatible(pattern_str: str) -> bool:
    """Check if pattern is compatible with Hyperscan."""
    # Lookahead/lookbehind not supported
    if stdlib_re.search(r'\(\?[=!<]', pattern_str):
        return False
    # Unicode escapes in character classes not supported
    if '\\u' in pattern_str or '\\U' in pattern_str:
        return False
    # Backreferences not supported
    if stdlib_re.search(r'\\[1-9]', pattern_str):
        return False
    # Large patterns with many alternations cause DFA state explosion
    alternation_count = pattern_str.count('|')
    if alternation_count > 30:
        return False
    # Long patterns tend to fail compilation
    if len(pattern_str) > 500:
        return False
    # Nested quantifiers can cause issues
    if stdlib_re.search(r'\{[^}]+\}\s*\{', pattern_str):
        return False
    return True


@dataclass
class PatternInfo:
    """Metadata for a pattern in the Hyperscan database."""
    pattern_id: int
    entity_type: str
    confidence: float
    group_idx: int
    original_pattern: Any  # regex.Pattern for group extraction


class HyperscanDetector(BaseDetector):
    """
    High-performance pattern detector using Intel Hyperscan.

    Compiles compatible patterns into a single Hyperscan database for SIMD-accelerated
    scanning. Incompatible patterns (lookahead/lookbehind) run via standard regex.
    Falls back completely to standard detector if Hyperscan unavailable.
    """

    name = "pattern"
    tier = Tier.PATTERN

    _database: Optional[Any] = None
    _pattern_info: Dict[int, PatternInfo] = {}
    _fallback_patterns: List[Tuple[Any, str, float, int]] = []  # Patterns run via regex
    _initialized: bool = False
    _fallback_detector: Optional['PatternDetector'] = None

    def __init__(self):
        """Initialize the Hyperscan detector."""
        if not _HYPERSCAN_AVAILABLE:
            from .detector import PatternDetector
            self._fallback_detector = PatternDetector()
            return

        if not HyperscanDetector._initialized:
            self._compile_database()

    @classmethod
    def _compile_database(cls):
        """Compile compatible patterns into a Hyperscan database."""
        if cls._initialized:
            return

        expressions = []
        ids = []
        flags = []
        cls._fallback_patterns = []

        # Identify compatible patterns (fast pre-check)
        for i, (pattern, entity_type, confidence, group_idx) in enumerate(PATTERNS):
            pattern_str = pattern.pattern

            # Check if pattern is Hyperscan-compatible
            if not _is_hyperscan_compatible(pattern_str):
                cls._fallback_patterns.append((pattern, entity_type, confidence, group_idx))
                continue

            # Check pattern size (Hyperscan has limits)
            if len(pattern_str) > 5000:
                cls._fallback_patterns.append((pattern, entity_type, confidence, group_idx))
                continue

            # Add to compilation batch
            cls._pattern_info[i] = PatternInfo(
                pattern_id=i,
                entity_type=entity_type,
                confidence=confidence,
                group_idx=group_idx,
                original_pattern=pattern,
            )
            expressions.append(pattern_str.encode('utf-8'))
            ids.append(i)
            flags.append(hyperscan.HS_FLAG_SOM_LEFTMOST | hyperscan.HS_FLAG_UTF8)

        # Try batch compilation
        if expressions:
            try:
                cls._database = hyperscan.Database(mode=hyperscan.HS_MODE_BLOCK)
                cls._database.compile(
                    expressions=expressions,
                    ids=ids,
                    flags=flags,
                )
                cls._initialized = True
                logger.info(
                    f"Compiled {len(expressions)} patterns into Hyperscan database, "
                    f"{len(cls._fallback_patterns)} use regex fallback"
                )
            except hyperscan.error as e:
                # Batch compilation failed - fall back to individual testing
                logger.warning(f"Batch compilation failed ({e}), testing patterns individually...")
                cls._compile_database_individual()
            except Exception as e:
                logger.error(f"Failed to compile Hyperscan database: {e}")
                cls._database = None
        else:
            logger.warning("No patterns compatible with Hyperscan, using regex fallback")
            cls._database = None

    @classmethod
    def _compile_database_individual(cls):
        """Fallback: compile patterns one by one to identify problematic ones."""
        expressions = []
        ids = []
        flags = []

        # Clear and rebuild
        good_patterns = {}
        cls._fallback_patterns = []

        for i, info in list(cls._pattern_info.items()):
            pattern_str = info.original_pattern.pattern
            pattern_bytes = pattern_str.encode('utf-8')

            try:
                test_db = hyperscan.Database(mode=hyperscan.HS_MODE_BLOCK)
                test_db.compile(
                    expressions=[pattern_bytes],
                    ids=[0],
                    flags=[hyperscan.HS_FLAG_SOM_LEFTMOST | hyperscan.HS_FLAG_UTF8],
                )
                good_patterns[i] = info
                expressions.append(pattern_bytes)
                ids.append(i)
                flags.append(hyperscan.HS_FLAG_SOM_LEFTMOST | hyperscan.HS_FLAG_UTF8)
            except Exception:
                cls._fallback_patterns.append((
                    info.original_pattern,
                    info.entity_type,
                    info.confidence,
                    info.group_idx,
                ))

        cls._pattern_info = good_patterns

        if expressions:
            try:
                cls._database = hyperscan.Database(mode=hyperscan.HS_MODE_BLOCK)
                cls._database.compile(expressions=expressions, ids=ids, flags=flags)
                cls._initialized = True
                logger.info(
                    f"Compiled {len(expressions)} patterns (individual mode), "
                    f"{len(cls._fallback_patterns)} use regex fallback"
                )
            except Exception as e:
                logger.error(f"Individual compilation also failed: {e}")
                cls._database = None

    def detect(self, text: str) -> List[Span]:
        """Detect entities using Hyperscan acceleration."""
        # Fallback if Hyperscan not available or compilation failed
        if self._fallback_detector or not HyperscanDetector._database:
            if self._fallback_detector:
                return self._fallback_detector.detect(text)
            from .detector import PatternDetector
            return PatternDetector().detect(text)

        spans = []
        text_bytes = text.encode('utf-8')

        # Collect raw matches from Hyperscan
        raw_matches: List[Tuple[int, int, int]] = []  # (pattern_id, start, end)

        def on_match(pattern_id: int, start: int, end: int, flags: int, context: Any):
            raw_matches.append((pattern_id, start, end))
            return None  # Continue scanning

        try:
            HyperscanDetector._database.scan(text_bytes, on_match)
        except Exception as e:
            logger.warning(f"Hyperscan scan failed, falling back: {e}")
            from .detector import PatternDetector
            return PatternDetector().detect(text)

        # Also run fallback patterns (those with lookahead/lookbehind)
        spans.extend(self._run_fallback_patterns(text))

        # Process Hyperscan matches with validation
        for pattern_id, byte_start, byte_end in raw_matches:
            info = self._pattern_info.get(pattern_id)
            if not info:
                continue

            # Convert byte positions to character positions
            try:
                start = len(text_bytes[:byte_start].decode('utf-8'))
                end = len(text_bytes[:byte_end].decode('utf-8'))
            except UnicodeDecodeError:
                continue

            value = text[start:end]

            # Apply group extraction if needed
            if info.group_idx > 0:
                match = info.original_pattern.match(value)
                if match and match.lastindex and info.group_idx <= match.lastindex:
                    group_value = match.group(info.group_idx)
                    if group_value:
                        # Adjust positions for group
                        group_start = value.find(group_value)
                        if group_start >= 0:
                            start = start + group_start
                            end = start + len(group_value)
                            value = group_value

            if not value or not value.strip():
                continue

            # Apply validators
            entity_type = info.entity_type
            confidence = info.confidence

            if entity_type == 'IP_ADDRESS' and not validate_ip(value):
                continue

            if entity_type in ('PHONE', 'PHONE_MOBILE', 'PHONE_HOME', 'PHONE_WORK', 'FAX'):
                if not validate_phone(value):
                    continue

            if entity_type in ('DATE', 'DATE_DOB'):
                # Re-match with original pattern for groups
                match = info.original_pattern.search(text[start:end+20] if end+20 <= len(text) else text[start:])
                if match and match.lastindex and match.lastindex >= 3:
                    try:
                        g1, g2, g3 = match.group(1), match.group(2), match.group(3)
                        if g1 and g2 and g3 and g1.isdigit() and g2.isdigit() and g3.isdigit():
                            if len(g1) == 4:
                                y, m, d = int(g1), int(g2), int(g3)
                            else:
                                m, d, y = int(g1), int(g2), int(g3)
                            if not validate_date(m, d, y):
                                continue
                    except (ValueError, IndexError):
                        pass

            if entity_type == 'AGE' and not validate_age(value):
                continue

            if entity_type == 'SSN' and not validate_ssn_context(text, start, confidence):
                continue

            if entity_type == 'CREDIT_CARD' and not validate_luhn(value):
                continue

            if entity_type == 'VIN' and confidence < 0.90:
                if not validate_vin(value):
                    continue

            if entity_type in ('NAME', 'NAME_PROVIDER', 'NAME_PATIENT', 'NAME_RELATIVE'):
                if is_false_positive_name(value):
                    continue

            span = Span(
                start=start,
                end=end,
                text=value,
                entity_type=entity_type,
                confidence=confidence,
                detector=self.name,
                tier=self.tier,
            )
            spans.append(span)

        return spans


    def _run_fallback_patterns(self, text: str) -> List[Span]:
        """Run patterns that aren't Hyperscan-compatible via standard regex."""
        spans = []

        for pattern, entity_type, confidence, group_idx in HyperscanDetector._fallback_patterns:
            for match in pattern.finditer(text):
                if group_idx > 0 and match.lastindex and group_idx <= match.lastindex:
                    value = match.group(group_idx)
                    start = match.start(group_idx)
                    end = match.end(group_idx)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()

                if not value or not value.strip():
                    continue

                # Apply validators (same as main detect)
                if not self._validate_match(text, value, start, end, entity_type, confidence, match):
                    continue

                span = Span(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=entity_type,
                    confidence=confidence,
                    detector=self.name,
                    tier=self.tier,
                )
                spans.append(span)

        return spans

    def _validate_match(
        self, text: str, value: str, start: int, end: int,
        entity_type: str, confidence: float, match: Any
    ) -> bool:
        """Validate a match based on entity type."""
        if entity_type == 'IP_ADDRESS' and not validate_ip(value):
            return False

        if entity_type in ('PHONE', 'PHONE_MOBILE', 'PHONE_HOME', 'PHONE_WORK', 'FAX'):
            if not validate_phone(value):
                return False

        if entity_type in ('DATE', 'DATE_DOB') and match and match.lastindex and match.lastindex >= 3:
            try:
                g1, g2, g3 = match.group(1), match.group(2), match.group(3)
                if g1 and g2 and g3 and g1.isdigit() and g2.isdigit() and g3.isdigit():
                    if len(g1) == 4:
                        y, m, d = int(g1), int(g2), int(g3)
                    else:
                        m, d, y = int(g1), int(g2), int(g3)
                    if not validate_date(m, d, y):
                        return False
            except (ValueError, IndexError):
                pass

        if entity_type == 'AGE' and not validate_age(value):
            return False

        if entity_type == 'SSN' and not validate_ssn_context(text, start, confidence):
            return False

        if entity_type == 'CREDIT_CARD' and not validate_luhn(value):
            return False

        if entity_type == 'VIN' and confidence < 0.90:
            if not validate_vin(value):
                return False

        if entity_type in ('NAME', 'NAME_PROVIDER', 'NAME_PATIENT', 'NAME_RELATIVE'):
            if is_false_positive_name(value):
                return False

        return True


def is_hyperscan_available() -> bool:
    """Check if Hyperscan is available and working."""
    return _HYPERSCAN_AVAILABLE and HyperscanDetector._initialized
