"""Comprehensive tests for core/labels.py.

Tests label primitives including:
- Label ID generation and validation
- Content hash computation
- Value normalization and hashing
- Label and LabelSet dataclasses
- Serialization/deserialization
"""

import pytest
import re
import time
import hashlib
from unittest.mock import patch, mock_open

from openlabels.core.labels import (
    generate_label_id,
    is_valid_label_id,
    compute_content_hash,
    compute_content_hash_file,
    is_valid_content_hash,
    normalize_value,
    compute_value_hash,
    is_valid_value_hash,
    VALUE_NORMALIZERS,
    Label,
    LabelSet,
    VirtualLabelPointer,
    labels_from_detection,
)


class TestLabelIdGeneration:
    """Tests for label ID generation."""

    def test_generate_label_id_format(self):
        """Generated ID should match ol_[12 hex chars] format."""
        label_id = generate_label_id()
        assert label_id.startswith("ol_")
        assert len(label_id) == 15  # "ol_" + 12 chars
        assert re.match(r'^ol_[a-f0-9]{12}$', label_id)

    def test_generate_label_id_uniqueness(self):
        """Generated IDs should be unique."""
        ids = [generate_label_id() for _ in range(1000)]
        assert len(set(ids)) == 1000, "Generated IDs should be unique"

    def test_generate_label_id_lowercase(self):
        """Generated IDs should be lowercase hex."""
        for _ in range(100):
            label_id = generate_label_id()
            hex_part = label_id[3:]
            assert hex_part == hex_part.lower()


class TestLabelIdValidation:
    """Tests for label ID validation."""

    def test_valid_label_id(self):
        """Valid label IDs should pass validation."""
        assert is_valid_label_id("ol_7f3a9b2c4d5e")
        assert is_valid_label_id("ol_000000000000")
        assert is_valid_label_id("ol_ffffffffffff")

    def test_invalid_label_id_no_prefix(self):
        """IDs without ol_ prefix should fail."""
        assert not is_valid_label_id("7f3a9b2c4d5e")
        assert not is_valid_label_id("xx_7f3a9b2c4d5e")

    def test_invalid_label_id_wrong_length(self):
        """IDs with wrong length should fail."""
        assert not is_valid_label_id("ol_7f3a9b2c4d5")  # 11 chars
        assert not is_valid_label_id("ol_7f3a9b2c4d5e1")  # 13 chars

    def test_invalid_label_id_uppercase(self):
        """Uppercase hex should fail."""
        assert not is_valid_label_id("ol_7F3A9B2C4D5E")

    def test_invalid_label_id_non_hex(self):
        """Non-hex characters should fail."""
        assert not is_valid_label_id("ol_7f3a9b2c4d5g")  # 'g' is not hex

    def test_generated_id_validates(self):
        """Generated IDs should pass validation."""
        for _ in range(100):
            label_id = generate_label_id()
            assert is_valid_label_id(label_id)


class TestContentHash:
    """Tests for content hash computation."""

    def test_compute_content_hash(self):
        """Content hash should be 12 lowercase hex chars."""
        content = b"Hello, World!"
        hash_result = compute_content_hash(content)
        assert len(hash_result) == 12
        assert re.match(r'^[a-f0-9]{12}$', hash_result)

    def test_content_hash_consistency(self):
        """Same content should produce same hash."""
        content = b"Test content"
        h1 = compute_content_hash(content)
        h2 = compute_content_hash(content)
        assert h1 == h2

    def test_content_hash_different_content(self):
        """Different content should produce different hashes."""
        h1 = compute_content_hash(b"Content A")
        h2 = compute_content_hash(b"Content B")
        assert h1 != h2

    def test_content_hash_empty(self):
        """Empty content should have a valid hash."""
        hash_result = compute_content_hash(b"")
        assert is_valid_content_hash(hash_result)
        # SHA-256 of empty string starts with e3b0c44298fc
        assert hash_result == "e3b0c44298fc"

    def test_content_hash_is_sha256_prefix(self):
        """Hash should be first 12 chars of SHA-256."""
        content = b"test"
        expected = hashlib.sha256(content).hexdigest()[:12].lower()
        assert compute_content_hash(content) == expected


class TestContentHashFile:
    """Tests for file-based content hash."""

    def test_compute_content_hash_file(self, tmp_path):
        """File hash should match content hash."""
        content = b"File content for testing"
        file_path = tmp_path / "test.txt"
        file_path.write_bytes(content)

        file_hash = compute_content_hash_file(str(file_path))
        content_hash = compute_content_hash(content)

        assert file_hash == content_hash

    def test_compute_content_hash_file_large(self, tmp_path):
        """Large file should be hashed correctly."""
        content = b"x" * (1024 * 1024)  # 1MB
        file_path = tmp_path / "large.bin"
        file_path.write_bytes(content)

        hash_result = compute_content_hash_file(str(file_path))
        assert is_valid_content_hash(hash_result)

    def test_compute_content_hash_file_empty(self, tmp_path):
        """Empty file should have valid hash."""
        file_path = tmp_path / "empty.txt"
        file_path.write_bytes(b"")

        hash_result = compute_content_hash_file(str(file_path))
        assert hash_result == "e3b0c44298fc"


class TestContentHashValidation:
    """Tests for content hash validation."""

    def test_valid_content_hash(self):
        """Valid hashes should pass."""
        assert is_valid_content_hash("e3b0c44298fc")
        assert is_valid_content_hash("000000000000")
        assert is_valid_content_hash("ffffffffffff")

    def test_invalid_content_hash_length(self):
        """Wrong length should fail."""
        assert not is_valid_content_hash("e3b0c44298f")  # 11 chars
        assert not is_valid_content_hash("e3b0c44298fc1")  # 13 chars

    def test_invalid_content_hash_uppercase(self):
        """Uppercase should fail."""
        assert not is_valid_content_hash("E3B0C44298FC")

    def test_invalid_content_hash_non_hex(self):
        """Non-hex characters should fail."""
        assert not is_valid_content_hash("e3b0c44298fg")


class TestValueNormalization:
    """Tests for value normalization."""

    def test_normalize_ssn(self):
        """SSN should have hyphens and spaces removed."""
        assert normalize_value("123-45-6789", "SSN") == "123456789"
        assert normalize_value("123 45 6789", "SSN") == "123456789"
        assert normalize_value("123-45 6789", "SSN") == "123456789"

    def test_normalize_credit_card(self):
        """Credit card should have separators removed."""
        assert normalize_value("1234-5678-9012-3456", "CREDIT_CARD") == "1234567890123456"
        assert normalize_value("1234 5678 9012 3456", "CREDIT_CARD") == "1234567890123456"

    def test_normalize_phone(self):
        """Phone should keep only digits and +."""
        assert normalize_value("+1 (555) 123-4567", "PHONE") == "+15551234567"
        assert normalize_value("555.123.4567", "PHONE") == "5551234567"

    def test_normalize_iban(self):
        """IBAN should be uppercase without spaces."""
        assert normalize_value("de89 3704 0044 0532 0130 00", "IBAN") == "DE89370400440532013000"

    def test_normalize_email(self):
        """Email should be lowercase trimmed."""
        assert normalize_value("  John@Example.COM  ", "EMAIL") == "john@example.com"

    def test_normalize_unknown_type(self):
        """Unknown type should just strip whitespace."""
        assert normalize_value("  test value  ", "UNKNOWN") == "test value"

    def test_normalizers_dict(self):
        """VALUE_NORMALIZERS should have expected keys."""
        assert "SSN" in VALUE_NORMALIZERS
        assert "CREDIT_CARD" in VALUE_NORMALIZERS
        assert "PHONE" in VALUE_NORMALIZERS
        assert "IBAN" in VALUE_NORMALIZERS
        assert "EMAIL" in VALUE_NORMALIZERS


class TestValueHash:
    """Tests for value hash computation."""

    def test_compute_value_hash_format(self):
        """Value hash should be 6 lowercase hex chars."""
        hash_result = compute_value_hash("test", "NAME")
        assert len(hash_result) == 6
        assert re.match(r'^[a-f0-9]{6}$', hash_result)

    def test_compute_value_hash_consistency(self):
        """Same normalized value should produce same hash."""
        h1 = compute_value_hash("123-45-6789", "SSN")
        h2 = compute_value_hash("123 45 6789", "SSN")  # Different format
        assert h1 == h2  # Same after normalization

    def test_compute_value_hash_different_values(self):
        """Different values should produce different hashes."""
        h1 = compute_value_hash("123-45-6789", "SSN")
        h2 = compute_value_hash("987-65-4321", "SSN")
        assert h1 != h2

    def test_is_valid_value_hash(self):
        """Valid value hashes should pass."""
        assert is_valid_value_hash("abcdef")
        assert is_valid_value_hash("000000")
        assert is_valid_value_hash("ffffff")

    def test_invalid_value_hash(self):
        """Invalid value hashes should fail."""
        assert not is_valid_value_hash("abcde")  # Too short
        assert not is_valid_value_hash("abcdefg")  # Too long
        assert not is_valid_value_hash("ABCDEF")  # Uppercase


class TestLabel:
    """Tests for Label dataclass."""

    def test_label_creation(self):
        """Label should be created with required fields."""
        label = Label(
            type="SSN",
            confidence=0.95,
            detector="checksum",
            value_hash="abc123",
        )
        assert label.type == "SSN"
        assert label.confidence == 0.95
        assert label.detector == "checksum"
        assert label.value_hash == "abc123"
        assert label.count == 1  # Default
        assert label.extensions is None  # Default

    def test_label_with_count(self):
        """Label should accept count."""
        label = Label(
            type="EMAIL",
            confidence=0.90,
            detector="pattern",
            value_hash="def456",
            count=5,
        )
        assert label.count == 5

    def test_label_with_extensions(self):
        """Label should accept extensions."""
        label = Label(
            type="NAME",
            confidence=0.85,
            detector="ml",
            value_hash="ghi789",
            extensions={"source": "presidio"},
        )
        assert label.extensions == {"source": "presidio"}

    def test_label_to_dict(self):
        """to_dict should use compact field names."""
        label = Label(
            type="SSN",
            confidence=0.956,
            detector="checksum",
            value_hash="abc123",
        )
        d = label.to_dict()

        assert d["t"] == "SSN"
        assert d["c"] == 0.96  # Rounded to 2 decimals
        assert d["d"] == "checksum"
        assert d["h"] == "abc123"
        assert "n" not in d  # Count=1 not included

    def test_label_to_dict_with_count(self):
        """to_dict should include count > 1."""
        label = Label(
            type="SSN",
            confidence=0.90,
            detector="pattern",
            value_hash="abc123",
            count=3,
        )
        d = label.to_dict()
        assert d["n"] == 3

    def test_label_to_dict_with_extensions(self):
        """to_dict should include extensions."""
        label = Label(
            type="SSN",
            confidence=0.90,
            detector="pattern",
            value_hash="abc123",
            extensions={"key": "value"},
        )
        d = label.to_dict()
        assert d["x"] == {"key": "value"}

    def test_label_from_dict(self):
        """from_dict should deserialize correctly."""
        d = {
            "t": "SSN",
            "c": 0.95,
            "d": "checksum",
            "h": "abc123",
        }
        label = Label.from_dict(d)

        assert label.type == "SSN"
        assert label.confidence == 0.95
        assert label.detector == "checksum"
        assert label.value_hash == "abc123"
        assert label.count == 1
        assert label.extensions is None

    def test_label_from_dict_with_count(self):
        """from_dict should parse count."""
        d = {"t": "SSN", "c": 0.95, "d": "pattern", "h": "abc123", "n": 5}
        label = Label.from_dict(d)
        assert label.count == 5

    def test_label_from_dict_validation(self):
        """from_dict should validate types."""
        with pytest.raises(ValueError, match="type must be string"):
            Label.from_dict({"t": 123, "c": 0.95, "d": "x", "h": "abc"})

        with pytest.raises(ValueError, match="confidence must be numeric"):
            Label.from_dict({"t": "SSN", "c": "high", "d": "x", "h": "abc"})

        with pytest.raises(ValueError, match="detector must be string"):
            Label.from_dict({"t": "SSN", "c": 0.9, "d": 123, "h": "abc"})

        with pytest.raises(ValueError, match="value_hash must be string"):
            Label.from_dict({"t": "SSN", "c": 0.9, "d": "x", "h": 123})


class TestLabelSet:
    """Tests for LabelSet dataclass."""

    def test_labelset_creation(self):
        """LabelSet should be created with required fields."""
        labels = [Label("SSN", 0.95, "checksum", "abc123")]
        label_set = LabelSet(
            version=1,
            label_id="ol_7f3a9b2c4d5e",
            content_hash="e3b0c44298fc",
            labels=labels,
            source="openlabels:1.0.0",
            timestamp=1234567890,
        )
        assert label_set.version == 1
        assert label_set.label_id == "ol_7f3a9b2c4d5e"
        assert len(label_set.labels) == 1

    def test_labelset_validates_version(self):
        """LabelSet should reject invalid version."""
        with pytest.raises(ValueError, match="Unsupported version"):
            LabelSet(
                version=2,
                label_id="ol_7f3a9b2c4d5e",
                content_hash="e3b0c44298fc",
                labels=[],
                source="test",
                timestamp=123,
            )

    def test_labelset_validates_label_id(self):
        """LabelSet should reject invalid label ID."""
        with pytest.raises(ValueError, match="Invalid label ID"):
            LabelSet(
                version=1,
                label_id="invalid",
                content_hash="e3b0c44298fc",
                labels=[],
                source="test",
                timestamp=123,
            )

    def test_labelset_validates_content_hash(self):
        """LabelSet should reject invalid content hash."""
        with pytest.raises(ValueError, match="Invalid content hash"):
            LabelSet(
                version=1,
                label_id="ol_7f3a9b2c4d5e",
                content_hash="invalid",
                labels=[],
                source="test",
                timestamp=123,
            )

    def test_labelset_to_dict(self):
        """to_dict should use compact field names."""
        labels = [Label("SSN", 0.95, "checksum", "abc123")]
        label_set = LabelSet(
            version=1,
            label_id="ol_7f3a9b2c4d5e",
            content_hash="e3b0c44298fc",
            labels=labels,
            source="openlabels:1.0.0",
            timestamp=1234567890,
        )
        d = label_set.to_dict()

        assert d["v"] == 1
        assert d["id"] == "ol_7f3a9b2c4d5e"
        assert d["hash"] == "e3b0c44298fc"
        assert len(d["labels"]) == 1
        assert d["src"] == "openlabels:1.0.0"
        assert d["ts"] == 1234567890

    def test_labelset_to_json_compact(self):
        """to_json compact should have no whitespace."""
        label_set = LabelSet(
            version=1,
            label_id="ol_7f3a9b2c4d5e",
            content_hash="e3b0c44298fc",
            labels=[],
            source="test",
            timestamp=123,
        )
        json_str = label_set.to_json(compact=True)
        assert " " not in json_str
        assert "\n" not in json_str

    def test_labelset_to_json_pretty(self):
        """to_json pretty should be formatted."""
        label_set = LabelSet(
            version=1,
            label_id="ol_7f3a9b2c4d5e",
            content_hash="e3b0c44298fc",
            labels=[],
            source="test",
            timestamp=123,
        )
        json_str = label_set.to_json(compact=False)
        assert "\n" in json_str

    def test_labelset_from_dict(self):
        """from_dict should deserialize correctly."""
        d = {
            "v": 1,
            "id": "ol_7f3a9b2c4d5e",
            "hash": "e3b0c44298fc",
            "labels": [{"t": "SSN", "c": 0.95, "d": "checksum", "h": "abc123"}],
            "src": "test",
            "ts": 123,
        }
        label_set = LabelSet.from_dict(d)

        assert label_set.version == 1
        assert label_set.label_id == "ol_7f3a9b2c4d5e"
        assert len(label_set.labels) == 1
        assert label_set.labels[0].type == "SSN"

    def test_labelset_from_json(self):
        """from_json should parse JSON string."""
        json_str = '{"v":1,"id":"ol_7f3a9b2c4d5e","hash":"e3b0c44298fc","labels":[],"src":"test","ts":123}'
        label_set = LabelSet.from_json(json_str)
        assert label_set.label_id == "ol_7f3a9b2c4d5e"

    def test_labelset_roundtrip(self):
        """to_json/from_json should roundtrip correctly."""
        labels = [Label("SSN", 0.95, "checksum", "abc123", count=2)]
        original = LabelSet(
            version=1,
            label_id="ol_7f3a9b2c4d5e",
            content_hash="e3b0c44298fc",
            labels=labels,
            source="openlabels:1.0.0",
            timestamp=1234567890,
        )

        json_str = original.to_json()
        restored = LabelSet.from_json(json_str)

        assert restored.label_id == original.label_id
        assert restored.content_hash == original.content_hash
        assert len(restored.labels) == len(original.labels)
        assert restored.labels[0].count == 2

    def test_labelset_create(self):
        """create should generate IDs and compute hash."""
        labels = [Label("SSN", 0.95, "checksum", "abc123")]
        content = b"test content"

        label_set = LabelSet.create(labels, content)

        assert is_valid_label_id(label_set.label_id)
        assert label_set.content_hash == compute_content_hash(content)
        assert label_set.version == 1
        assert label_set.timestamp > 0

    def test_labelset_create_with_existing_id(self):
        """create should preserve existing label ID."""
        labels = []
        existing_id = "ol_7f3a9b2c4d5e"

        label_set = LabelSet.create(labels, b"content", label_id=existing_id)

        assert label_set.label_id == existing_id


class TestVirtualLabelPointer:
    """Tests for VirtualLabelPointer."""

    def test_pointer_to_string(self):
        """to_string should format as labelID:content_hash."""
        pointer = VirtualLabelPointer(
            label_id="ol_7f3a9b2c4d5e",
            content_hash="e3b0c44298fc",
        )
        assert pointer.to_string() == "ol_7f3a9b2c4d5e:e3b0c44298fc"

    def test_pointer_str_method(self):
        """__str__ should call to_string."""
        pointer = VirtualLabelPointer("ol_7f3a9b2c4d5e", "e3b0c44298fc")
        assert str(pointer) == "ol_7f3a9b2c4d5e:e3b0c44298fc"

    def test_pointer_from_string(self):
        """from_string should parse correctly."""
        pointer = VirtualLabelPointer.from_string("ol_7f3a9b2c4d5e:e3b0c44298fc")
        assert pointer.label_id == "ol_7f3a9b2c4d5e"
        assert pointer.content_hash == "e3b0c44298fc"

    def test_pointer_from_string_with_whitespace(self):
        """from_string should handle whitespace."""
        pointer = VirtualLabelPointer.from_string("  ol_7f3a9b2c4d5e:e3b0c44298fc  ")
        assert pointer.label_id == "ol_7f3a9b2c4d5e"

    def test_pointer_from_string_invalid(self):
        """from_string should reject invalid format."""
        with pytest.raises(ValueError, match="Invalid virtual label"):
            VirtualLabelPointer.from_string("invalid_format")

        with pytest.raises(ValueError, match="Invalid virtual label"):
            VirtualLabelPointer.from_string("too:many:colons")


class TestLabelsFromDetection:
    """Tests for labels_from_detection helper."""

    def test_labels_from_detection_basic(self):
        """Should convert detection results to labels."""
        class MockSpan:
            def __init__(self, entity_type, text, confidence):
                self.entity_type = entity_type
                self.text = text
                self.confidence = confidence

        entity_counts = {"SSN": 2, "EMAIL": 1}
        spans = [
            MockSpan("SSN", "123-45-6789", 0.95),
            MockSpan("SSN", "987-65-4321", 0.90),
            MockSpan("EMAIL", "test@example.com", 0.85),
        ]

        labels = labels_from_detection(entity_counts, spans)

        assert len(labels) == 2  # Two distinct entity types
        ssn_label = next(l for l in labels if l.type == "SSN")
        assert ssn_label.count == 2
        assert ssn_label.confidence == 0.925  # Average of 0.95 and 0.90

    def test_labels_from_detection_empty(self):
        """Should handle empty input."""
        labels = labels_from_detection({}, [])
        assert labels == []

    def test_labels_from_detection_with_detector(self):
        """Should use detector attribute from span."""
        class MockSpan:
            def __init__(self):
                self.entity_type = "SSN"
                self.text = "123-45-6789"
                self.confidence = 0.95
                self.detector = "checksum"

        labels = labels_from_detection({"SSN": 1}, [MockSpan()])
        assert labels[0].detector == "checksum"
