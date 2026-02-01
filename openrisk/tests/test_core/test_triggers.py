"""
Tests for openlabels.core.triggers module.

Tests scan trigger decision logic based on entities and context.
"""

import pytest
from unittest.mock import Mock, patch


class TestScanTrigger:
    """Tests for ScanTrigger enum."""

    def test_trigger_values(self):
        """Should have expected trigger values."""
        from openlabels.core.triggers import ScanTrigger

        assert ScanTrigger.NO_LABELS.value == "no_labels"
        assert ScanTrigger.PUBLIC_ACCESS.value == "public_access"
        assert ScanTrigger.ORG_WIDE.value == "org_wide"
        assert ScanTrigger.NO_ENCRYPTION.value == "no_encryption"
        assert ScanTrigger.STALE_DATA.value == "stale_data"
        assert ScanTrigger.LOW_CONFIDENCE_HIGH_RISK.value == "low_conf_high_risk"

    def test_all_triggers_unique(self):
        """All trigger values should be unique."""
        from openlabels.core.triggers import ScanTrigger

        values = [t.value for t in ScanTrigger]
        assert len(values) == len(set(values))


class TestShouldScan:
    """Tests for should_scan function."""

    @pytest.fixture
    def mock_context(self):
        """Create a default context."""
        from openlabels.adapters.base import NormalizedContext
        return NormalizedContext(
            exposure="PRIVATE",
            encryption="customer_managed",
            has_classification=True,
            staleness_days=30,
        )

    @pytest.fixture
    def mock_entity(self):
        """Create a default entity."""
        from openlabels.adapters.base import Entity
        return Entity(type="EMAIL", count=1, confidence=0.9, source="test")

    def test_no_labels_triggers_scan(self, mock_context):
        """Should trigger scan when no labels."""
        from openlabels.core.triggers import should_scan, ScanTrigger

        mock_context.has_classification = False
        should, triggers = should_scan([], mock_context)

        assert should is True
        assert ScanTrigger.NO_LABELS in triggers

    def test_empty_entities_triggers_scan(self, mock_context):
        """Should trigger scan when entities list is empty."""
        from openlabels.core.triggers import should_scan, ScanTrigger

        should, triggers = should_scan([], mock_context)

        assert should is True
        assert ScanTrigger.NO_LABELS in triggers

    def test_none_entities_triggers_scan(self, mock_context):
        """Should trigger scan when entities is None."""
        from openlabels.core.triggers import should_scan, ScanTrigger

        should, triggers = should_scan(None, mock_context)

        assert should is True
        assert ScanTrigger.NO_LABELS in triggers

    def test_public_access_triggers_scan(self, mock_context, mock_entity):
        """Should trigger scan for PUBLIC exposure."""
        from openlabels.core.triggers import should_scan, ScanTrigger

        mock_context.exposure = "PUBLIC"
        should, triggers = should_scan([mock_entity], mock_context)

        assert should is True
        assert ScanTrigger.PUBLIC_ACCESS in triggers

    def test_org_wide_triggers_scan(self, mock_context, mock_entity):
        """Should trigger scan for ORG_WIDE exposure."""
        from openlabels.core.triggers import should_scan, ScanTrigger

        mock_context.exposure = "ORG_WIDE"
        should, triggers = should_scan([mock_entity], mock_context)

        assert should is True
        assert ScanTrigger.ORG_WIDE in triggers

    def test_no_encryption_triggers_scan(self, mock_context, mock_entity):
        """Should trigger scan when no encryption."""
        from openlabels.core.triggers import should_scan, ScanTrigger

        mock_context.encryption = "none"
        should, triggers = should_scan([mock_entity], mock_context)

        assert should is True
        assert ScanTrigger.NO_ENCRYPTION in triggers

    def test_stale_data_triggers_scan(self, mock_context, mock_entity):
        """Should trigger scan for stale data (>365 days)."""
        from openlabels.core.triggers import should_scan, ScanTrigger

        mock_context.staleness_days = 400
        should, triggers = should_scan([mock_entity], mock_context)

        assert should is True
        assert ScanTrigger.STALE_DATA in triggers

    def test_staleness_at_threshold(self, mock_context, mock_entity):
        """Should not trigger at exactly 365 days."""
        from openlabels.core.triggers import should_scan, ScanTrigger

        mock_context.staleness_days = 365
        should, triggers = should_scan([mock_entity], mock_context)

        # 365 is not > 365
        assert ScanTrigger.STALE_DATA not in triggers

    def test_low_confidence_high_risk_triggers_scan(self, mock_context):
        """Should trigger scan for high-risk entity with low confidence."""
        from openlabels.core.triggers import should_scan, ScanTrigger
        from openlabels.adapters.base import Entity

        # SSN has weight 10, confidence 0.65 < 0.80 threshold
        ssn_entity = Entity(type="SSN", count=1, confidence=0.65, source="test")
        should, triggers = should_scan([ssn_entity], mock_context)

        assert should is True
        assert ScanTrigger.LOW_CONFIDENCE_HIGH_RISK in triggers

    def test_high_confidence_high_risk_no_trigger(self, mock_context):
        """Should not trigger for high-risk entity with high confidence."""
        from openlabels.core.triggers import should_scan, ScanTrigger
        from openlabels.adapters.base import Entity

        # SSN has weight 10, confidence 0.95 >= 0.80 threshold
        ssn_entity = Entity(type="SSN", count=1, confidence=0.95, source="test")
        should, triggers = should_scan([ssn_entity], mock_context)

        assert ScanTrigger.LOW_CONFIDENCE_HIGH_RISK not in triggers

    def test_low_confidence_low_risk_no_trigger(self, mock_context):
        """Should not trigger for low-risk entity with low confidence."""
        from openlabels.core.triggers import should_scan, ScanTrigger
        from openlabels.adapters.base import Entity

        # EMAIL has weight 5 (< 8 threshold)
        email_entity = Entity(type="EMAIL", count=1, confidence=0.4, source="test")
        should, triggers = should_scan([email_entity], mock_context)

        assert ScanTrigger.LOW_CONFIDENCE_HIGH_RISK not in triggers

    def test_private_encrypted_high_confidence_no_scan(self, mock_context, mock_entity):
        """Should not scan when private, encrypted, high confidence."""
        from openlabels.core.triggers import should_scan

        # Default context is PRIVATE, customer_managed, 30 days
        should, triggers = should_scan([mock_entity], mock_context)

        assert should is False
        assert triggers == []

    def test_multiple_triggers(self, mock_context):
        """Should accumulate multiple triggers."""
        from openlabels.core.triggers import should_scan, ScanTrigger
        from openlabels.adapters.base import Entity

        mock_context.exposure = "PUBLIC"
        mock_context.encryption = "none"
        mock_context.staleness_days = 500

        entity = Entity(type="SSN", count=1, confidence=0.5, source="test")
        should, triggers = should_scan([entity], mock_context)

        assert should is True
        assert ScanTrigger.PUBLIC_ACCESS in triggers
        assert ScanTrigger.NO_ENCRYPTION in triggers
        assert ScanTrigger.STALE_DATA in triggers
        assert ScanTrigger.LOW_CONFIDENCE_HIGH_RISK in triggers

    def test_exposure_enum_support(self, mock_context, mock_entity):
        """Should handle ExposureLevel enum."""
        from openlabels.core.triggers import should_scan, ScanTrigger
        from openlabels.adapters.base import ExposureLevel

        mock_context.exposure = ExposureLevel.PUBLIC
        should, triggers = should_scan([mock_entity], mock_context)

        assert ScanTrigger.PUBLIC_ACCESS in triggers


class TestGetTriggerDescriptions:
    """Tests for get_trigger_descriptions function."""

    def test_descriptions_for_all_triggers(self):
        """Should return descriptions for all trigger types."""
        from openlabels.core.triggers import get_trigger_descriptions, ScanTrigger

        all_triggers = list(ScanTrigger)
        descriptions = get_trigger_descriptions(all_triggers)

        assert len(descriptions) == len(all_triggers)
        for desc in descriptions:
            assert isinstance(desc, str)
            assert len(desc) > 0

    def test_description_content(self):
        """Descriptions should be meaningful."""
        from openlabels.core.triggers import get_trigger_descriptions, ScanTrigger

        descriptions = get_trigger_descriptions([ScanTrigger.NO_LABELS])
        assert "label" in descriptions[0].lower()

        descriptions = get_trigger_descriptions([ScanTrigger.PUBLIC_ACCESS])
        assert "public" in descriptions[0].lower()

    def test_empty_triggers(self):
        """Should return empty list for empty triggers."""
        from openlabels.core.triggers import get_trigger_descriptions

        descriptions = get_trigger_descriptions([])
        assert descriptions == []


class TestCalculateScanPriority:
    """Tests for calculate_scan_priority function."""

    @pytest.fixture
    def mock_context(self):
        """Create a default context."""
        from openlabels.adapters.base import NormalizedContext
        return NormalizedContext(
            exposure="PRIVATE",
            encryption="customer_managed",
        )

    def test_private_no_triggers_low_priority(self, mock_context):
        """Private with no triggers should be low priority."""
        from openlabels.core.triggers import calculate_scan_priority

        priority = calculate_scan_priority(mock_context, [])
        assert priority < 25

    def test_public_high_priority(self, mock_context):
        """Public exposure should give high priority."""
        from openlabels.core.triggers import calculate_scan_priority

        mock_context.exposure = "PUBLIC"
        priority = calculate_scan_priority(mock_context, [])
        assert priority >= 50

    def test_internal_medium_priority(self, mock_context):
        """Internal exposure should give medium priority."""
        from openlabels.core.triggers import calculate_scan_priority

        mock_context.exposure = "INTERNAL"
        priority = calculate_scan_priority(mock_context, [])
        assert 10 <= priority < 50

    def test_no_encryption_boost(self, mock_context):
        """NO_ENCRYPTION trigger should boost priority."""
        from openlabels.core.triggers import calculate_scan_priority, ScanTrigger

        base = calculate_scan_priority(mock_context, [])
        with_trigger = calculate_scan_priority(
            mock_context, [ScanTrigger.NO_ENCRYPTION]
        )
        assert with_trigger > base

    def test_low_confidence_high_risk_boost(self, mock_context):
        """LOW_CONFIDENCE_HIGH_RISK trigger should boost priority."""
        from openlabels.core.triggers import calculate_scan_priority, ScanTrigger

        base = calculate_scan_priority(mock_context, [])
        with_trigger = calculate_scan_priority(
            mock_context, [ScanTrigger.LOW_CONFIDENCE_HIGH_RISK]
        )
        assert with_trigger > base

    def test_priority_capped_at_100(self, mock_context):
        """Priority should never exceed 100."""
        from openlabels.core.triggers import calculate_scan_priority, ScanTrigger

        mock_context.exposure = "PUBLIC"
        all_triggers = list(ScanTrigger)

        priority = calculate_scan_priority(mock_context, all_triggers)
        assert priority <= 100

    def test_multiple_triggers_cumulative(self, mock_context):
        """Multiple triggers should increase priority."""
        from openlabels.core.triggers import calculate_scan_priority, ScanTrigger

        single = calculate_scan_priority(mock_context, [ScanTrigger.NO_LABELS])
        multiple = calculate_scan_priority(
            mock_context,
            [ScanTrigger.NO_LABELS, ScanTrigger.NO_ENCRYPTION, ScanTrigger.STALE_DATA]
        )
        assert multiple > single


class TestNeedsScan:
    """Tests for needs_scan convenience function."""

    def test_returns_bool(self):
        """Should return boolean."""
        from openlabels.core.triggers import needs_scan
        from openlabels.adapters.base import NormalizedContext

        context = NormalizedContext(
            exposure="PRIVATE",
            has_classification=True,
            encryption="customer_managed",
        )

        result = needs_scan([], context)
        assert isinstance(result, bool)

    def test_matches_should_scan(self):
        """Should match should_scan first return value."""
        from openlabels.core.triggers import needs_scan, should_scan
        from openlabels.adapters.base import NormalizedContext, Entity

        context = NormalizedContext(
            exposure="PUBLIC",
            has_classification=True,
        )
        entity = Entity(type="SSN", count=1, confidence=0.5, source="test")

        needs = needs_scan([entity], context)
        should, _ = should_scan([entity], context)

        assert needs == should


class TestGetScanUrgency:
    """Tests for get_scan_urgency function."""

    @pytest.fixture
    def mock_context(self):
        """Create a default context."""
        from openlabels.adapters.base import NormalizedContext
        return NormalizedContext(
            exposure="PRIVATE",
            encryption="customer_managed",
            has_classification=True,
        )

    def test_returns_none_when_no_scan_needed(self, mock_context):
        """Should return NONE when scan not needed."""
        from openlabels.core.triggers import get_scan_urgency
        from openlabels.adapters.base import Entity

        entity = Entity(type="EMAIL", count=1, confidence=0.95, source="test")
        urgency = get_scan_urgency([entity], mock_context)

        assert urgency == "NONE"

    def test_returns_low_for_basic_triggers(self, mock_context):
        """Should return LOW for basic triggers."""
        from openlabels.core.triggers import get_scan_urgency

        mock_context.has_classification = False
        urgency = get_scan_urgency([], mock_context)

        assert urgency in ["LOW", "MEDIUM", "HIGH", "IMMEDIATE"]

    def test_returns_immediate_for_critical(self, mock_context):
        """Should return IMMEDIATE for critical scenarios."""
        from openlabels.core.triggers import get_scan_urgency
        from openlabels.adapters.base import Entity

        mock_context.exposure = "PUBLIC"
        mock_context.encryption = "none"
        entity = Entity(type="SSN", count=1, confidence=0.5, source="test")

        urgency = get_scan_urgency([entity], mock_context)

        assert urgency == "IMMEDIATE"

    def test_valid_urgency_values(self, mock_context):
        """Should only return valid urgency values."""
        from openlabels.core.triggers import get_scan_urgency

        valid_urgencies = {"IMMEDIATE", "HIGH", "MEDIUM", "LOW", "NONE"}

        for exposure in ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]:
            mock_context.exposure = exposure
            urgency = get_scan_urgency([], mock_context)
            assert urgency in valid_urgencies


class TestConstants:
    """Tests for module constants."""

    def test_confidence_threshold(self):
        """Confidence threshold should be reasonable."""
        from openlabels.core.triggers import CONFIDENCE_THRESHOLD

        assert 0.0 < CONFIDENCE_THRESHOLD < 1.0
        assert CONFIDENCE_THRESHOLD == 0.80

    def test_high_risk_weight_threshold(self):
        """High risk weight threshold should be reasonable."""
        from openlabels.core.triggers import HIGH_RISK_WEIGHT_THRESHOLD

        assert 1 <= HIGH_RISK_WEIGHT_THRESHOLD <= 10
        assert HIGH_RISK_WEIGHT_THRESHOLD == 8

    def test_staleness_threshold(self):
        """Staleness threshold should be one year."""
        from openlabels.core.triggers import STALENESS_THRESHOLD_DAYS

        assert STALENESS_THRESHOLD_DAYS == 365
