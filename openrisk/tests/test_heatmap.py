"""Tests for HeatmapNode dataclass."""

import pytest

from openlabels.dashboard_models import HeatmapNode


class TestHeatmapNode:
    def test_init_defaults(self):
        node = HeatmapNode(name="test", path="/test")
        assert node.name == "test"
        assert node.path == "/test"
        assert node.entity_counts == {}
        assert node.total_score == 0
        assert node.file_count == 0
        assert node.children == {}

    def test_add_entity_single(self):
        node = HeatmapNode(name="test", path="/test")
        node.add_entity("SSN", 5)
        assert node.entity_counts["SSN"] == 5

    def test_add_entity_accumulates(self):
        node = HeatmapNode(name="test", path="/test")
        node.add_entity("SSN", 5)
        node.add_entity("SSN", 3)
        assert node.entity_counts["SSN"] == 8

    def test_add_entity_multiple_types(self):
        node = HeatmapNode(name="test", path="/test")
        node.add_entity("SSN", 5)
        node.add_entity("EMAIL", 10)
        node.add_entity("PHONE", 3)
        assert node.entity_counts == {"SSN": 5, "EMAIL": 10, "PHONE": 3}

    def test_add_entity_default_count(self):
        node = HeatmapNode(name="test", path="/test")
        node.add_entity("SSN")
        node.add_entity("SSN")
        assert node.entity_counts["SSN"] == 2

    def test_total_entities_empty(self):
        node = HeatmapNode(name="test", path="/test")
        assert node.total_entities == 0

    def test_total_entities_sums_all_types(self):
        node = HeatmapNode(name="test", path="/test")
        node.add_entity("SSN", 5)
        node.add_entity("EMAIL", 10)
        node.add_entity("PHONE", 3)
        assert node.total_entities == 18

    def test_get_intensity_zero_max(self):
        node = HeatmapNode(name="test", path="/test")
        node.add_entity("SSN", 5)
        assert node.get_intensity("SSN", 0) == 0.0

    def test_get_intensity_missing_type(self):
        node = HeatmapNode(name="test", path="/test")
        assert node.get_intensity("SSN", 10) == 0.0

    def test_get_intensity_full(self):
        node = HeatmapNode(name="test", path="/test")
        node.add_entity("SSN", 10)
        assert node.get_intensity("SSN", 10) == 1.0

    def test_get_intensity_half(self):
        node = HeatmapNode(name="test", path="/test")
        node.add_entity("SSN", 5)
        assert node.get_intensity("SSN", 10) == 0.5

    def test_get_intensity_capped_at_one(self):
        node = HeatmapNode(name="test", path="/test")
        node.add_entity("SSN", 20)
        assert node.get_intensity("SSN", 10) == 1.0

    def test_children_hierarchy(self):
        root = HeatmapNode(name="root", path="")
        child1 = HeatmapNode(name="child1", path="/child1")
        child2 = HeatmapNode(name="child2", path="/child2")

        root.children["child1"] = child1
        root.children["child2"] = child2

        assert len(root.children) == 2
        assert root.children["child1"].name == "child1"

    def test_aggregation_pattern(self):
        """Test the common pattern of aggregating counts up a hierarchy."""
        root = HeatmapNode(name="root", path="")
        folder = HeatmapNode(name="folder", path="/folder")
        file1 = HeatmapNode(name="file1.txt", path="/folder/file1.txt")
        file2 = HeatmapNode(name="file2.txt", path="/folder/file2.txt")

        root.children["folder"] = folder
        folder.children["file1.txt"] = file1
        folder.children["file2.txt"] = file2

        # Simulate scan results
        file1.add_entity("SSN", 3)
        file1.add_entity("EMAIL", 2)
        file2.add_entity("SSN", 1)
        file2.add_entity("PHONE", 5)

        # Aggregate up
        for entity, count in file1.entity_counts.items():
            folder.add_entity(entity, count)
            root.add_entity(entity, count)
        for entity, count in file2.entity_counts.items():
            folder.add_entity(entity, count)
            root.add_entity(entity, count)

        assert folder.entity_counts == {"SSN": 4, "EMAIL": 2, "PHONE": 5}
        assert root.entity_counts == {"SSN": 4, "EMAIL": 2, "PHONE": 5}
        assert folder.total_entities == 11
        assert root.total_entities == 11
