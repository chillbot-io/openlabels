"""
Tests for Entity Merger.

Tests entity merging strategies:
- CONSERVATIVE_UNION (max count, max confidence)
- SUM_COUNTS (sum counts, max confidence)
- FIRST_WINS (first adapter wins)
- Exposure level merging
- Context merging
"""

import pytest

from openlabels.core.merger import (
    MergeStrategy,
    MergedEntity,
    MergeResult,
    merge_inputs,
    merge_inputs_full,
    merge_entities,
    get_highest_exposure,
    merge_contexts,
    deduplicate_positions,
    entities_to_counts,
    counts_to_entities,
    EXPOSURE_ORDER,
)
from openlabels.adapters.base import Entity, NormalizedContext, NormalizedInput, ExposureLevel
from openlabels.core.constants import CONFIDENCE_WHEN_NO_SPANS


class TestMergeStrategy:
    """Tests for MergeStrategy enum."""

    def test_conservative_union_value(self):
        assert MergeStrategy.CONSERVATIVE_UNION.value == "conservative_union"

    def test_sum_counts_value(self):
        assert MergeStrategy.SUM_COUNTS.value == "sum_counts"

    def test_first_wins_value(self):
        assert MergeStrategy.FIRST_WINS.value == "first_wins"


class TestMergedEntity:
    """Tests for MergedEntity dataclass."""

    def test_basic_construction(self):
        entity = MergedEntity(
            type="SSN",
            count=5,
            confidence=0.95,
            sources=["macie", "scanner"],
        )

        assert entity.type == "SSN"
        assert entity.count == 5
        assert entity.confidence == 0.95
        assert "macie" in entity.sources
        assert "scanner" in entity.sources

    def test_default_positions(self):
        entity = MergedEntity(
            type="EMAIL",
            count=3,
            confidence=0.90,
            sources=["scanner"],
        )

        assert entity.positions == []


class TestMergeResult:
    """Tests for MergeResult dataclass."""

    def test_get_entity_found(self):
        entities = [
            MergedEntity(type="SSN", count=1, confidence=0.9, sources=["a"]),
            MergedEntity(type="EMAIL", count=2, confidence=0.8, sources=["b"]),
        ]
        result = MergeResult(
            entities=entities,
            entity_counts={"SSN": 1, "EMAIL": 2},
            average_confidence=0.85,
            exposure="PRIVATE",
            sources={"a", "b"},
            input_count=2,
        )

        found = result.get_entity("SSN")

        assert found is not None
        assert found.type == "SSN"

    def test_get_entity_case_insensitive(self):
        entities = [
            MergedEntity(type="SSN", count=1, confidence=0.9, sources=["a"]),
        ]
        result = MergeResult(
            entities=entities,
            entity_counts={"SSN": 1},
            average_confidence=0.9,
            exposure="PRIVATE",
            sources={"a"},
            input_count=1,
        )

        assert result.get_entity("ssn") is not None
        assert result.get_entity("Ssn") is not None

    def test_get_entity_not_found(self):
        result = MergeResult(
            entities=[],
            entity_counts={},
            average_confidence=0.5,
            exposure="PRIVATE",
            sources=set(),
            input_count=0,
        )

        assert result.get_entity("SSN") is None

    def test_has_entity(self):
        entities = [
            MergedEntity(type="SSN", count=1, confidence=0.9, sources=["a"]),
        ]
        result = MergeResult(
            entities=entities,
            entity_counts={"SSN": 1},
            average_confidence=0.9,
            exposure="PRIVATE",
            sources={"a"},
            input_count=1,
        )

        assert result.has_entity("SSN") is True
        assert result.has_entity("EMAIL") is False


class TestMergeInputs:
    """Tests for merge_inputs() function."""

    def test_empty_inputs(self):
        entity_counts, confidence = merge_inputs([])

        assert entity_counts == {}
        assert confidence == CONFIDENCE_WHEN_NO_SPANS

    def test_single_input(self):
        inp = NormalizedInput(
            entities=[
                Entity(type="SSN", count=2, confidence=0.95, source="scanner"),
            ],
            context=NormalizedContext(exposure="PRIVATE"),
        )

        entity_counts, confidence = merge_inputs([inp])

        assert entity_counts["SSN"] == 2
        assert confidence == 0.95

    def test_conservative_union_takes_max_count(self):
        """CONSERVATIVE_UNION should take max count from inputs."""
        inp1 = NormalizedInput(
            entities=[Entity(type="SSN", count=2, confidence=0.9, source="a")],
            context=NormalizedContext(exposure="PRIVATE"),
        )
        inp2 = NormalizedInput(
            entities=[Entity(type="SSN", count=5, confidence=0.8, source="b")],
            context=NormalizedContext(exposure="PRIVATE"),
        )

        entity_counts, _ = merge_inputs([inp1, inp2], MergeStrategy.CONSERVATIVE_UNION)

        assert entity_counts["SSN"] == 5  # Max of 2 and 5

    def test_conservative_union_takes_max_confidence(self):
        """CONSERVATIVE_UNION should take max confidence from inputs."""
        inp1 = NormalizedInput(
            entities=[Entity(type="SSN", count=2, confidence=0.8, source="a")],
            context=NormalizedContext(exposure="PRIVATE"),
        )
        inp2 = NormalizedInput(
            entities=[Entity(type="SSN", count=5, confidence=0.95, source="b")],
            context=NormalizedContext(exposure="PRIVATE"),
        )

        _, confidence = merge_inputs([inp1, inp2], MergeStrategy.CONSERVATIVE_UNION)

        assert confidence == 0.95  # Max of 0.8 and 0.95

    def test_sum_counts_adds_counts(self):
        """SUM_COUNTS should add counts from inputs."""
        inp1 = NormalizedInput(
            entities=[Entity(type="SSN", count=2, confidence=0.9, source="a")],
            context=NormalizedContext(exposure="PRIVATE"),
        )
        inp2 = NormalizedInput(
            entities=[Entity(type="SSN", count=3, confidence=0.8, source="b")],
            context=NormalizedContext(exposure="PRIVATE"),
        )

        entity_counts, _ = merge_inputs([inp1, inp2], MergeStrategy.SUM_COUNTS)

        assert entity_counts["SSN"] == 5  # 2 + 3

    def test_first_wins_keeps_first(self):
        """FIRST_WINS should keep first adapter's values."""
        inp1 = NormalizedInput(
            entities=[Entity(type="SSN", count=2, confidence=0.8, source="a")],
            context=NormalizedContext(exposure="PRIVATE"),
        )
        inp2 = NormalizedInput(
            entities=[Entity(type="SSN", count=10, confidence=0.99, source="b")],
            context=NormalizedContext(exposure="PRIVATE"),
        )

        entity_counts, confidence = merge_inputs([inp1, inp2], MergeStrategy.FIRST_WINS)

        assert entity_counts["SSN"] == 2  # First value
        assert confidence == 0.8  # First confidence


class TestMergeInputsFull:
    """Tests for merge_inputs_full() function."""

    def test_returns_merge_result(self):
        inp = NormalizedInput(
            entities=[Entity(type="SSN", count=1, confidence=0.9, source="a")],
            context=NormalizedContext(exposure="PRIVATE"),
        )

        result = merge_inputs_full([inp])

        assert isinstance(result, MergeResult)

    def test_collects_sources(self):
        inp1 = NormalizedInput(
            entities=[Entity(type="SSN", count=1, confidence=0.9, source="macie")],
            context=NormalizedContext(exposure="PRIVATE"),
        )
        inp2 = NormalizedInput(
            entities=[Entity(type="EMAIL", count=2, confidence=0.8, source="scanner")],
            context=NormalizedContext(exposure="PRIVATE"),
        )

        result = merge_inputs_full([inp1, inp2])

        assert "macie" in result.sources
        assert "scanner" in result.sources

    def test_tracks_input_count(self):
        inputs = [
            NormalizedInput(entities=[], context=NormalizedContext(exposure="PRIVATE")),
            NormalizedInput(entities=[], context=NormalizedContext(exposure="PRIVATE")),
            NormalizedInput(entities=[], context=NormalizedContext(exposure="PRIVATE")),
        ]

        result = merge_inputs_full(inputs)

        assert result.input_count == 3

    def test_normalizes_entity_types(self):
        """Entity types should be normalized to uppercase."""
        inp = NormalizedInput(
            entities=[Entity(type="ssn", count=1, confidence=0.9, source="a")],
            context=NormalizedContext(exposure="PRIVATE"),
        )

        result = merge_inputs_full([inp])

        # The merged entity type should be uppercase
        assert result.entities[0].type.upper() == result.entities[0].type


class TestMergeEntities:
    """Tests for merge_entities() function."""

    def test_merges_entity_lists(self):
        list1 = [Entity(type="SSN", count=2, confidence=0.9, source="a")]
        list2 = [Entity(type="EMAIL", count=3, confidence=0.85, source="b")]

        merged = merge_entities([list1, list2])

        types = {e.type for e in merged}
        assert "SSN" in types
        assert "EMAIL" in types

    def test_merges_same_type_conservative(self):
        list1 = [Entity(type="SSN", count=2, confidence=0.8, source="a")]
        list2 = [Entity(type="SSN", count=5, confidence=0.95, source="b")]

        merged = merge_entities([list1, list2], MergeStrategy.CONSERVATIVE_UNION)

        ssn = [e for e in merged if e.type == "SSN"][0]
        assert ssn.count == 5  # Max
        assert ssn.confidence == 0.95  # Max

    def test_collects_all_sources(self):
        list1 = [Entity(type="SSN", count=1, confidence=0.9, source="macie")]
        list2 = [Entity(type="SSN", count=2, confidence=0.8, source="dlp")]

        merged = merge_entities([list1, list2])

        ssn = [e for e in merged if e.type == "SSN"][0]
        assert "macie" in ssn.sources
        assert "dlp" in ssn.sources


class TestExposureHelpers:
    """Tests for exposure-related functions."""

    def test_exposure_order_constant(self):
        """EXPOSURE_ORDER should be lowest to highest."""
        assert EXPOSURE_ORDER == ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]

    def test_get_highest_exposure_empty(self):
        result = get_highest_exposure([])
        assert result == "PRIVATE"

    def test_get_highest_exposure_single(self):
        inp = NormalizedInput(
            entities=[],
            context=NormalizedContext(exposure="INTERNAL"),
        )
        result = get_highest_exposure([inp])
        assert result == "INTERNAL"

    def test_get_highest_exposure_multiple(self):
        inputs = [
            NormalizedInput(entities=[], context=NormalizedContext(exposure="PRIVATE")),
            NormalizedInput(entities=[], context=NormalizedContext(exposure="PUBLIC")),
            NormalizedInput(entities=[], context=NormalizedContext(exposure="INTERNAL")),
        ]

        result = get_highest_exposure(inputs)

        assert result == "PUBLIC"  # Highest

    def test_get_highest_exposure_with_enum(self):
        """Should handle ExposureLevel enum."""
        inp = NormalizedInput(
            entities=[],
            context=NormalizedContext(exposure=ExposureLevel.PUBLIC),
        )

        result = get_highest_exposure([inp])

        assert result == "PUBLIC"


class TestMergeContexts:
    """Tests for merge_contexts() function."""

    def test_empty_contexts(self):
        result = merge_contexts([])
        assert result.exposure == "PRIVATE"

    def test_single_context(self):
        ctx = NormalizedContext(exposure="INTERNAL", owner="user1")

        result = merge_contexts([ctx])

        assert result.exposure == "INTERNAL"
        assert result.owner == "user1"

    def test_takes_highest_exposure(self):
        ctx1 = NormalizedContext(exposure="PRIVATE")
        ctx2 = NormalizedContext(exposure="PUBLIC")

        result = merge_contexts([ctx1, ctx2])

        assert result.exposure == "PUBLIC"

    def test_worst_case_cross_account(self):
        """Should take worst case for cross_account_access."""
        ctx1 = NormalizedContext(exposure="PRIVATE", cross_account_access=False)
        ctx2 = NormalizedContext(exposure="PRIVATE", cross_account_access=True)

        result = merge_contexts([ctx1, ctx2])

        assert result.cross_account_access is True

    def test_worst_case_anonymous_access(self):
        """Should take worst case for anonymous_access."""
        ctx1 = NormalizedContext(exposure="PRIVATE", anonymous_access=False)
        ctx2 = NormalizedContext(exposure="PRIVATE", anonymous_access=True)

        result = merge_contexts([ctx1, ctx2])

        assert result.anonymous_access is True

    def test_any_classification_is_good(self):
        """Should preserve any classification."""
        ctx1 = NormalizedContext(exposure="PRIVATE", has_classification=False)
        ctx2 = NormalizedContext(exposure="PRIVATE", has_classification=True)

        result = merge_contexts([ctx1, ctx2])

        assert result.has_classification is True

    def test_max_staleness(self):
        """Should take maximum staleness."""
        ctx1 = NormalizedContext(exposure="PRIVATE", staleness_days=10)
        ctx2 = NormalizedContext(exposure="PRIVATE", staleness_days=30)

        result = merge_contexts([ctx1, ctx2])

        assert result.staleness_days == 30


class TestDeduplicatePositions:
    """Tests for deduplicate_positions() function."""

    def test_empty_positions(self):
        result = deduplicate_positions([])
        assert result == []

    def test_no_overlap(self):
        positions = [(0, 10), (20, 30), (40, 50)]
        result = deduplicate_positions(positions)
        assert result == [(0, 10), (20, 30), (40, 50)]

    def test_removes_duplicates(self):
        positions = [(0, 10), (0, 10), (20, 30)]
        result = deduplicate_positions(positions)
        assert result == [(0, 10), (20, 30)]

    def test_merges_overlapping(self):
        positions = [(0, 10), (5, 15)]
        result = deduplicate_positions(positions)
        assert result == [(0, 15)]

    def test_merges_adjacent(self):
        positions = [(0, 10), (10, 20)]
        result = deduplicate_positions(positions)
        assert result == [(0, 20)]

    def test_complex_merge(self):
        positions = [(0, 5), (3, 8), (10, 15), (12, 20), (25, 30)]
        result = deduplicate_positions(positions)
        assert result == [(0, 8), (10, 20), (25, 30)]


class TestEntitiesToCounts:
    """Tests for entities_to_counts() function."""

    def test_empty_list(self):
        result = entities_to_counts([])
        assert result == {}

    def test_single_entity(self):
        entities = [Entity(type="SSN", count=3, confidence=0.9, source="a")]
        result = entities_to_counts(entities)
        assert result == {"SSN": 3}

    def test_multiple_same_type(self):
        """Should sum counts for same type."""
        entities = [
            Entity(type="SSN", count=2, confidence=0.9, source="a"),
            Entity(type="SSN", count=3, confidence=0.8, source="b"),
        ]
        result = entities_to_counts(entities)
        assert result == {"SSN": 5}

    def test_normalizes_type(self):
        """Should normalize entity type to uppercase."""
        entities = [Entity(type="ssn", count=1, confidence=0.9, source="a")]
        result = entities_to_counts(entities)
        # Type should be normalized to uppercase
        assert "SSN" in result
        assert result["SSN"] == 1


class TestCountsToEntities:
    """Tests for counts_to_entities() function."""

    def test_empty_counts(self):
        result = counts_to_entities({})
        assert result == []

    def test_creates_entities(self):
        counts = {"SSN": 5, "EMAIL": 10}
        result = counts_to_entities(counts)

        assert len(result) == 2
        types = {e.type for e in result}
        assert "SSN" in types
        assert "EMAIL" in types

    def test_uses_provided_source(self):
        result = counts_to_entities({"SSN": 1}, source="custom")
        assert result[0].source == "custom"

    def test_uses_provided_confidence(self):
        result = counts_to_entities({"SSN": 1}, confidence=0.99)
        assert result[0].confidence == 0.99
