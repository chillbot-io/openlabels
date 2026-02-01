"""Tests for files/processor.py - file processing orchestration.

Tests cover:
- FileProcessor initialization
- PHI field to span conversion
- Model loading
- Job management
- Extractor creation
- Feature flags
"""

import io
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from scrubiq.types import Span, Tier


# =============================================================================
# PHI FIELDS TO SPANS TESTS
# =============================================================================

class TestPhiFieldsToSpans:
    """Tests for phi_fields_to_spans function."""

    def test_converts_phi_fields_to_spans(self):
        """Converts PHI field dict to Span objects."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "Patient Name: John Smith DOB: 01/15/1980"
        phi_fields = {
            "patient_name": {
                "value": "John Smith",
                "phi_category": "name",
                "confidence": 0.9,
                "validated": False,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)

        assert len(spans) == 1
        assert spans[0].text == "John Smith"
        assert spans[0].entity_type == "NAME"
        assert spans[0].confidence == 0.9

    def test_empty_phi_fields_returns_empty(self):
        """Empty PHI fields returns empty list."""
        from scrubiq.files.processor import phi_fields_to_spans

        spans = phi_fields_to_spans("Some text", {})
        assert spans == []

        spans = phi_fields_to_spans("Some text", None)
        assert spans == []

    def test_empty_text_returns_empty(self):
        """Empty text returns empty list."""
        from scrubiq.files.processor import phi_fields_to_spans

        phi_fields = {
            "test": {"value": "test", "phi_category": "name"}
        }

        spans = phi_fields_to_spans("", phi_fields)
        assert spans == []

    def test_boosts_confidence_for_validated_fields(self):
        """Validated fields get confidence boost."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "SSN: 123-45-6789"
        phi_fields = {
            "ssn": {
                "value": "123-45-6789",
                "phi_category": "ssn",
                "confidence": 0.85,
                "validated": True,  # Passed checksum validation
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)

        assert len(spans) == 1
        # Confidence should be boosted by 0.1
        assert spans[0].confidence == 0.95

    def test_confidence_capped_at_1(self):
        """Confidence boost doesn't exceed 1.0."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "MRN: 12345"
        phi_fields = {
            "mrn": {
                "value": "12345",
                "phi_category": "mrn",
                "confidence": 0.98,
                "validated": True,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)

        assert len(spans) == 1
        assert spans[0].confidence == 1.0

    def test_finds_all_occurrences(self):
        """Finds all occurrences of value in text."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "John called. John left a message."
        phi_fields = {
            "patient_name": {
                "value": "John",
                "phi_category": "name",
                "confidence": 0.9,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)

        # Should find both occurrences
        assert len(spans) == 2
        positions = [s.start for s in spans]
        assert 0 in positions
        assert 13 in positions

    def test_uses_word_boundaries(self):
        """Uses word boundaries to avoid partial matches."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "Johnson called. John left."
        phi_fields = {
            "patient_name": {
                "value": "John",
                "phi_category": "name",
                "confidence": 0.9,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)

        # Should only find "John", not "Johnson"
        assert len(spans) == 1
        assert spans[0].text == "John"

    def test_maps_phi_categories_correctly(self):
        """Maps PHI categories to entity types correctly."""
        from scrubiq.files.processor import phi_fields_to_spans

        test_cases = [
            ("name", "NAME"),
            ("address", "ADDRESS"),
            ("date", "DATE"),
            ("phone", "PHONE"),
            ("ssn", "SSN"),
            ("mrn", "MRN"),
            ("email", "EMAIL"),
            ("health_plan_id", "HEALTH_PLAN_ID"),
        ]

        for phi_category, expected_entity_type in test_cases:
            text = f"Value: TestValue123"
            phi_fields = {
                "field": {
                    "value": "TestValue123",
                    "phi_category": phi_category,
                    "confidence": 0.9,
                },
            }

            spans = phi_fields_to_spans(text, phi_fields)

            assert len(spans) == 1
            assert spans[0].entity_type == expected_entity_type, f"Failed for {phi_category}"

    def test_uses_structured_tier(self):
        """Spans have STRUCTURED tier (high authority)."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "DOB: 01/15/1980"
        phi_fields = {
            "dob": {
                "value": "01/15/1980",
                "phi_category": "date",
                "confidence": 0.9,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)

        assert len(spans) == 1
        assert spans[0].tier == Tier.STRUCTURED

    def test_skips_fields_without_value(self):
        """Skips fields without value."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "Some text"
        phi_fields = {
            "empty_field": {
                "value": None,
                "phi_category": "name",
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)
        assert len(spans) == 0

    def test_skips_fields_without_phi_category(self):
        """Skips fields without phi_category."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "John Smith"
        phi_fields = {
            "unknown_field": {
                "value": "John Smith",
                "phi_category": None,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)
        assert len(spans) == 0

    def test_unknown_category_maps_to_unique_id(self):
        """Unknown PHI category maps to UNIQUE_ID."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "CustomID: ABC123"
        phi_fields = {
            "custom": {
                "value": "ABC123",
                "phi_category": "unknown_type",
                "confidence": 0.9,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)

        assert len(spans) == 1
        assert spans[0].entity_type == "UNIQUE_ID"

    def test_case_insensitive_matching(self):
        """Matches values case-insensitively."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "Patient: JOHN SMITH"
        phi_fields = {
            "name": {
                "value": "John Smith",
                "phi_category": "name",
                "confidence": 0.9,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)

        # Should match "JOHN SMITH"
        assert len(spans) == 1
        assert spans[0].text == "JOHN SMITH"

    def test_includes_detector_and_field_name(self):
        """Detector field includes field name."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "John Smith"
        phi_fields = {
            "patient_name": {
                "value": "John Smith",
                "phi_category": "name",
                "confidence": 0.9,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields, detector_name="test_detector")

        assert len(spans) == 1
        assert "test_detector" in spans[0].detector
        assert "patient_name" in spans[0].detector

    def test_handles_regex_special_characters(self):
        """Handles values with regex special characters."""
        from scrubiq.files.processor import phi_fields_to_spans

        text = "Email: john.smith+test@example.com"
        phi_fields = {
            "email": {
                "value": "john.smith+test@example.com",
                "phi_category": "email",
                "confidence": 0.9,
            },
        }

        spans = phi_fields_to_spans(text, phi_fields)

        # Should not crash on special chars, should find match
        assert len(spans) == 1


# =============================================================================
# PHI CATEGORY MAPPING TESTS
# =============================================================================

class TestPhiCategoryMapping:
    """Tests for PHI_CATEGORY_TO_ENTITY_TYPE mapping."""

    def test_all_expected_categories_mapped(self):
        """All expected PHI categories are mapped."""
        from scrubiq.files.processor import PHI_CATEGORY_TO_ENTITY_TYPE

        expected_categories = [
            'name', 'address', 'date', 'phone', 'fax', 'email',
            'ssn', 'mrn', 'health_plan_id', 'account_number',
            'license_number', 'vehicle_id', 'device_id',
            'url', 'ip_address', 'biometric', 'photo', 'other_unique_id',
        ]

        for category in expected_categories:
            assert category in PHI_CATEGORY_TO_ENTITY_TYPE


# =============================================================================
# FILE PROCESSOR INITIALIZATION TESTS
# =============================================================================

class TestFileProcessorInit:
    """Tests for FileProcessor initialization."""

    def test_init_with_defaults(self):
        """FileProcessor initializes with default settings."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine') as mock_ocr:
            with patch('scrubiq.files.processor.JobManager') as mock_job_mgr:
                mock_ocr.return_value = MagicMock()
                mock_job_mgr.return_value = MagicMock()

                from scrubiq.files.processor import FileProcessor
                fp = FileProcessor(mock_scrubiq)

                assert fp.cr == mock_scrubiq
                assert fp.enable_face_detection is True
                assert fp.enable_signature_detection is True
                assert fp.enable_metadata_stripping is True
                assert fp.enable_image_redaction is True
                assert fp.face_redaction_method == "blur"

    def test_init_with_ocr_engine(self):
        """FileProcessor accepts OCR engine."""
        mock_scrubiq = MagicMock()
        mock_ocr = MagicMock()

        with patch('scrubiq.files.processor.JobManager'):
            from scrubiq.files.processor import FileProcessor
            fp = FileProcessor(mock_scrubiq, ocr_engine=mock_ocr)

            assert fp.ocr_engine == mock_ocr

    def test_init_feature_flags(self):
        """FileProcessor respects feature flags."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                from scrubiq.files.processor import FileProcessor
                fp = FileProcessor(
                    mock_scrubiq,
                    enable_face_detection=False,
                    enable_signature_detection=False,
                    enable_metadata_stripping=False,
                    enable_image_redaction=False,
                    face_redaction_method="fill",
                )

                assert fp.enable_face_detection is False
                assert fp.enable_signature_detection is False
                assert fp.enable_metadata_stripping is False
                assert fp.enable_image_redaction is False
                assert fp.face_redaction_method == "fill"

    def test_init_creates_default_extractors(self):
        """FileProcessor creates default extractors."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                with patch('scrubiq.files.processor.PDFExtractor') as mock_pdf:
                    with patch('scrubiq.files.processor.DOCXExtractor') as mock_docx:
                        with patch('scrubiq.files.processor.XLSXExtractor') as mock_xlsx:
                            with patch('scrubiq.files.processor.ImageExtractor') as mock_img:
                                with patch('scrubiq.files.processor.TextExtractor') as mock_txt:
                                    with patch('scrubiq.files.processor.RTFExtractor') as mock_rtf:
                                        from scrubiq.files.processor import FileProcessor
                                        fp = FileProcessor(mock_scrubiq)

                                        # Should have created default extractors
                                        assert len(fp._default_extractors) == 6


# =============================================================================
# EXTRACTOR CREATION TESTS
# =============================================================================

class TestExtractorCreation:
    """Tests for _create_extractors method."""

    def test_create_extractors_without_temp_dir(self):
        """Creates extractors without temp directory."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                with patch('scrubiq.files.processor.PDFExtractor') as mock_pdf:
                    with patch('scrubiq.files.processor.DOCXExtractor'):
                        with patch('scrubiq.files.processor.XLSXExtractor'):
                            with patch('scrubiq.files.processor.ImageExtractor'):
                                with patch('scrubiq.files.processor.TextExtractor'):
                                    with patch('scrubiq.files.processor.RTFExtractor'):
                                        from scrubiq.files.processor import FileProcessor
                                        fp = FileProcessor(mock_scrubiq)

                                        extractors = fp._create_extractors(temp_dir=None)

                                        assert len(extractors) == 6

    def test_create_extractors_with_temp_dir(self):
        """Creates extractors with temp directory."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"
        mock_temp_dir = MagicMock()

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                with patch('scrubiq.files.processor.PDFExtractor') as mock_pdf:
                    with patch('scrubiq.files.processor.DOCXExtractor'):
                        with patch('scrubiq.files.processor.XLSXExtractor'):
                            with patch('scrubiq.files.processor.ImageExtractor') as mock_img:
                                with patch('scrubiq.files.processor.TextExtractor'):
                                    with patch('scrubiq.files.processor.RTFExtractor'):
                                        from scrubiq.files.processor import FileProcessor
                                        fp = FileProcessor(mock_scrubiq)

                                        extractors = fp._create_extractors(temp_dir=mock_temp_dir)

                                        # PDF and Image extractors should get temp_dir
                                        mock_pdf.assert_called()
                                        mock_img.assert_called()


# =============================================================================
# MODEL LOADING TESTS
# =============================================================================

class TestModelLoading:
    """Tests for model loading functionality."""

    def test_start_model_loading_starts_ocr(self):
        """start_model_loading initiates OCR loading."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"
        mock_ocr = MagicMock()
        mock_ocr.is_available = True
        mock_ocr.is_initialized = False

        with patch('scrubiq.files.processor.JobManager'):
            from scrubiq.files.processor import FileProcessor
            fp = FileProcessor(mock_scrubiq, ocr_engine=mock_ocr)
            fp.enable_face_detection = False  # Skip face detection

            fp.start_model_loading()

            mock_ocr.start_loading.assert_called_once()

    def test_start_model_loading_skips_initialized_ocr(self):
        """start_model_loading skips already initialized OCR."""
        mock_scrubiq = MagicMock()
        mock_ocr = MagicMock()
        mock_ocr.is_available = True
        mock_ocr.is_initialized = True  # Already initialized

        with patch('scrubiq.files.processor.JobManager'):
            from scrubiq.files.processor import FileProcessor
            fp = FileProcessor(mock_scrubiq, ocr_engine=mock_ocr)
            fp.enable_face_detection = False

            fp.start_model_loading()

            mock_ocr.start_loading.assert_not_called()

    def test_await_models_ready_returns_true_when_ready(self):
        """await_models_ready returns True when models ready."""
        mock_scrubiq = MagicMock()
        mock_ocr = MagicMock()
        mock_ocr.await_ready.return_value = True

        with patch('scrubiq.files.processor.JobManager'):
            from scrubiq.files.processor import FileProcessor
            fp = FileProcessor(mock_scrubiq, ocr_engine=mock_ocr)
            fp.enable_face_detection = False

            # Mock the face_protector property to return None
            with patch.object(FileProcessor, 'face_protector', new_callable=PropertyMock) as mock_fp:
                mock_fp.return_value = None
                result = fp.await_models_ready(timeout=1.0)

            assert result is True


# =============================================================================
# IMAGE MIME TYPES TESTS
# =============================================================================

class TestImageMimeTypes:
    """Tests for MIME type constants."""

    def test_image_mime_types(self):
        """IMAGE_MIME_TYPES contains common image types."""
        from scrubiq.files.processor import IMAGE_MIME_TYPES

        assert 'image/jpeg' in IMAGE_MIME_TYPES
        assert 'image/png' in IMAGE_MIME_TYPES
        assert 'image/tiff' in IMAGE_MIME_TYPES
        assert 'image/webp' in IMAGE_MIME_TYPES
        assert 'image/gif' in IMAGE_MIME_TYPES
        assert 'image/bmp' in IMAGE_MIME_TYPES

    def test_visual_redaction_mime_types(self):
        """VISUAL_REDACTION_MIME_TYPES includes images and PDF."""
        from scrubiq.files.processor import VISUAL_REDACTION_MIME_TYPES, IMAGE_MIME_TYPES

        # Should include all image types
        for mime_type in IMAGE_MIME_TYPES:
            assert mime_type in VISUAL_REDACTION_MIME_TYPES

        # Should include PDF
        assert 'application/pdf' in VISUAL_REDACTION_MIME_TYPES


# =============================================================================
# LAZY LOADING TESTS
# =============================================================================

class TestLazyLoading:
    """Tests for lazy-loaded components."""

    def test_metadata_stripper_lazy_loaded(self):
        """Metadata stripper is lazy loaded."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                from scrubiq.files.processor import FileProcessor
                fp = FileProcessor(mock_scrubiq)

                # Should be None initially
                assert fp._metadata_stripper is None

    def test_face_protector_lazy_loaded(self):
        """Face protector is lazy loaded."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                from scrubiq.files.processor import FileProcessor
                fp = FileProcessor(mock_scrubiq)

                # Should be None initially
                assert fp._face_protector is None

    def test_signature_protector_lazy_loaded(self):
        """Signature protector is lazy loaded."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                from scrubiq.files.processor import FileProcessor
                fp = FileProcessor(mock_scrubiq)

                # Should be None initially
                assert fp._signature_protector is None

    def test_image_store_lazy_loaded(self):
        """Image store is lazy loaded."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                from scrubiq.files.processor import FileProcessor
                fp = FileProcessor(mock_scrubiq)

                # Should be None initially
                assert fp._image_store is None


# =============================================================================
# THREAD POOL TESTS
# =============================================================================

class TestThreadPool:
    """Tests for thread pool configuration."""

    def test_default_max_workers(self):
        """Default max_workers is 1 for multi-page support."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                with patch('scrubiq.files.processor.ThreadPoolExecutor') as mock_executor:
                    from scrubiq.files.processor import FileProcessor
                    fp = FileProcessor(mock_scrubiq)

                    mock_executor.assert_called_with(max_workers=1)

    def test_custom_max_workers(self):
        """Custom max_workers can be specified."""
        mock_scrubiq = MagicMock()
        mock_scrubiq.config.models_dir = "/tmp/models"

        with patch('scrubiq.files.processor.OCREngine'):
            with patch('scrubiq.files.processor.JobManager'):
                with patch('scrubiq.files.processor.ThreadPoolExecutor') as mock_executor:
                    from scrubiq.files.processor import FileProcessor
                    fp = FileProcessor(mock_scrubiq, max_workers=4)

                    mock_executor.assert_called_with(max_workers=4)
