"""PatternDetector class for Tier 2 pattern-based detection."""

import logging
from typing import List

logger = logging.getLogger(__name__)

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
from ..constants import CONFIDENCE_MEDIUM


class PatternDetector(BaseDetector):
    """
    Tier 2 detector: Regex patterns with format validation.

    Confidence varies by pattern (0.70 - 0.96).
    Labeled patterns get higher confidence.
    """

    name = "pattern"
    tier = Tier.PATTERN

    def detect(self, text: str) -> List[Span]:
        spans = []

        for pattern, entity_type, confidence, group_idx in PATTERNS:
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

                if entity_type == 'IP_ADDRESS' and not validate_ip(value):
                    continue

                if entity_type in ('PHONE', 'PHONE_MOBILE', 'PHONE_HOME', 'PHONE_WORK', 'FAX'):
                    if not validate_phone(value):
                        continue

                if entity_type in ('DATE', 'DATE_DOB') and match.lastindex and match.lastindex >= 3:
                    try:
                        g1, g2, g3 = match.group(1), match.group(2), match.group(3)
                        if g1.isdigit() and g2.isdigit() and g3.isdigit():
                            if len(g1) == 4:
                                y, m, d = int(g1), int(g2), int(g3)
                            else:
                                m, d, y = int(g1), int(g2), int(g3)
                            if not validate_date(m, d, y):
                                continue
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Could not parse date groups for validation: {value}: {e}")

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
